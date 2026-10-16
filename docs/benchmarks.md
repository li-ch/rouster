# Rouster benchmarks — pre-registered experiment plan

Status: methodology frozen 2026-10-15, results pending. This doc
pre-registers the performance experiments before any are run: the
questions, setups, metrics, and the claims each experiment licenses.
Experiments may be executed in any order, in any session; each run
appends to the results ledger (§R) and never edits the frozen
sections above it. Motivation: the campaign fact sheet and white
paper currently claim design facts (memory-safe Rust, multi-core
async, per-neighbor BGP parallelism) and deliberately avoid the word
"fast" because no measurement exists
([implementation-plan.md](implementation-plan.md) §3 pre-registered
full-table soak tests). This plan is how that changes, honestly.

## Claim policy (frozen)

1. Descriptive claims ("ingests a full IPv4 table of N prefixes in
   X s on hardware H") are licensed by the median of ≥5 runs of the
   named experiment, published with raw artifacts.
2. Comparative claims ("within Y% of FRR", "faster than") further
   require §F fairness rules held for both sides, both directions
   published (if the competitor wins a metric, the table says so),
   and the versions pinned in the results ledger.
3. Unqualified "fast" never appears in any artifact. Claims name
   the dimension and the hardware.
4. No benchmark result is retuned after the fact. Re-runs with
   changed methodology get a new ledger entry and a note saying
   what changed; old entries stay.

## F. Fairness and reproducibility rules (frozen)

- Same host, same kernel, same Docker engine for every side of a
  comparison; versions recorded in the ledger entry.
- CPU pinning per daemon container (`--cpuset-cpus`), no shared
  cores between the system under test and the traffic generator.
- ≥5 measured runs after ≥1 warmup; report median and p95. Wall
  clocks come from the logs of both parties, cross-checked against
  an external observer (the host), never from one side's self
  report alone.
- Feeds are public and pinned by checksum (route-views MRT dumps:
  name the collector + dump timestamp + sha256 in the entry).
- Nothing that only one side can do is scored (e.g. no credit for
  features the competitor's config disables); where configuration
  matters, both configs are committed under `docker/bench/`.
- macOS Docker Desktop note: the VM's CPU scheduling adds noise.
  If no Linux host is available, run on the Mac, mark the ledger
  entry `host=darwin-vm`, and treat cross-side deltas <2× as
  unresolved (see decision D4).

## The experiments

### E1 — Full-table BGP ingestion (the headline)

- **Question**: how long does `bgpd` take to ingest a full IPv4
  view (~950k prefixes) from a single peer, and at what sustained
  UPDATE rate — against FRR 10.2.2 `bgpd` and BIRD 2.x `bird` under
  identical feeds?
- **Setup**: 3 SUT containers (rouster bgpd, FRR bgpd, BIRD), one
  injector container. Injector replays a route-views RIB dump
  (TABLE_DUMP_V2 MRT) converted to a BGP UPDATE stream.
  The SUT peers with the injector over eBGP; table completion is
  detected by the SUT's own RIB count reaching the dump's prefix
  count (polled via each side's native CLI) and cross-checked by
  injector-side queue-drain timestamps.
- **Metrics**: wall time first-UPDATE→table-complete; sustained
  UPDATEs/s; peak and final RSS; CPU seconds; kernel FIB
  programming completion if exporting to zebra/rousterd.
- **Tooling decision**: D1 (injector choice below).
- **Effort**: 1–2 days (mostly tooling; reusable for E2).
- **Licenses**: the core descriptive claim + the FRR/BIRD
  comparison, subject to §F.

### E2 — Churn and reconvergence under a flap storm

- **Question**: with W% of the table flapping (withdraw+reannounce
  cycles at rate R), what is reconvergence time, steady-state CPU,
  and does the session stay Established?
- **Setup**: as E1, injector generates flaps over the loaded table
  (10% at 100–1000 cycles/s; sweep 3 points).
- **Metrics**: time from storm start to quiescent RIB; CPU/RSS
  during; UPDATE/NOTIFICATION error counts; queue depth if
  observable.
- **Effort**: 1 day on top of E1 tooling.
- **Protocol addendum (2026-10-16, declared before the first §R
  run)**: the concrete S14-b shape — the table is the pinned 100k
  slice (announce file `announce-100k.announce`, the
  bench-mrt2announce derivative of the §R dump; sha256 recorded in
  the entry) loaded over ONE eBGP session by `scripts/bench-flap.py`
  (a stdlib-Python BGP speaker; the mrt-replay announce content with
  the one addition mrt-replay lacks — protocol-level
  withdraw/reannounce on the announcing session; identical tool and
  schedule on both SUTs per §F, so no vtysh-side clear which only
  one side could receive identically). Storm: a fixed subset of
  every 10th prefix (10% = ~10k) withdrawn and re-announced per
  round, N=10 rounds with steady-state waits between rounds;
  per-round reconvergence = reannounce-burst-done → SUT count
  restored (both the SUT's own main-table count and the kernel FIB
  count, the latter observed from a third container sharing the
  SUT's netns but pinned off the SUT cpuset). The 100–1000 cycles/s
  rate sweep stays deferred (this entry measures the round shape);
  full-table E2 is a later cell on the same harness.

### E3 — Session-establishment scaling (tests the multi-core claim)

- **Question**: does establishment throughput scale with cores?
  This is the architecture claim
  ([architecture.md](architecture.md): multi-core async from day
  one; per-neighbor BGP parallelism) put to a number.
- **Setup**: one injector opens N=8/32/128 concurrent BGP sessions
  to the SUT, staggered 0/s/1-per-100ms; run the SUT pinned to
  1, 2, 4 cores (repeat each cell).
- **Metrics**: wall time to all-N Established; sessions/s; CPU
  utilization per core count; failure count.
- **Effort**: 1 day.
- **Protocol addendum (2026-10-16, declared before the first §R
  run)**: the concrete S14-b shape — N ∈ {10, 50, 100} mrt-replay
  injector containers (one container per session: mrt-replay does
  not bind `--local-addr`, so distinct peer IPs need distinct
  containers; the binary is baked into the `docker/bench/
  Dockerfile.mrt-replay` fleet image), all released at a common
  T0 (busy-poll on the shared VM clock; the actual start-spread is
  recorded per run) against ONE SUT with N configured passive
  neighbors, SUT pinned to 1/2/4 cores (cpusets 4 / 4-5 / 4-7,
  injector fleet 0-3). Simultaneous start only — the staggered
  1-per-100ms variant stays deferred. Per-session table = the
  first 100 prefixes of the §R feed (--limit 100: session
  machinery, not table scale). Wall = min injector REPLAY-START →
  max REPLAY-ESTABLISHED, cross-checked by the SUT's own
  Established count.

### E4 — FIB programming rate (RIB → kernel)

- **Question**: how fast do routes reach the kernel through
  rousterd's RIB vs FRR zebra's, from an identical inbound stream?
- **Setup**: replay E1's feed (or a synthetic N=100k set) into
  `rousterd` with a bgpd feeding it, and into FRR zebra+bgpd;
  observe kernel route count over time from a third container
  (`ip -j route | jq length` polling at 1 Hz).
- **Metrics**: routes/s into the kernel; time to N% installed;
  RSS of the daemon pair.
- **Effort**: half a day.
- **Protocol addendum (2026-10-16, declared with the first §R
  run)**: the concrete S14-b shape — batch sizes B ∈ {1k, 10k,
  100k} of the pinned feed (mrt-replay --limit B, the E1 shape
  unpaced hold 90), 6 runs per size (1 warmup + 5 measured). The
  measured programming pass is the FIB install stream that follows
  the RIB load (rousterd's pipelined route_replace_batch reconcile,
  the F8 machinery); observation from a third container sharing the
  SUT's network namespace but pinned off the SUT cpuset
  (`ip route show proto 186 | wc -l`, 0.15 s / 0.4 s cadence at
  1-10k / 100k — the RTNL cost of the dump itself is disclosed).
  Metrics per size: wall first-kernel-route → B installed (the
  programming window) and launch → installed, routes/s, rousterd +
  bgpd CPU over the window, RSS of the pair, rcvbuf overruns,
  malformed/rejected. The FRR side is DERIVED from its ledgered
  full-table entry (zebra 9.67 CPU-s / 1,126,490 routes), not
  re-run — disclosed per the stream prompt.

### E5 — Memory per prefix

- **Question**: steady-state RSS with an empty table, 100k, and a
  full table — bytes per prefix per suite.
- **Setup**: same runs as E1 (no extra work if E1 logs RSS at each
  stage); compute deltas.
- **Effort**: hours, rides on E1.
- **Licenses**: the most defensible comparison claim class (memory
  is where C suites historically hurt); still §F-bound.

### E6 — The SAV tax (Rouster-only characterization)

- **Question**: what does native SAV cost, at the control plane and
  the data plane? No competitor exists; this is a scaling
  characterization, framed as such.
- **Setup**: with a loaded table (E1 feed): (a) control plane —
  RIB-churn-triggered SAV re-evaluation latency and rule-op counts
  at 10k/100k/full; (b) data plane — legitimate + spoofed traffic
  mix through an interface with the nft backend monitor-only vs
  drop vs disabled; measure forwarded packets/s (netperf or
  iperf3) and the monitor counters' fidelity.
- **Metrics**: re-evaluation latency p50/p95; rule ops per churn
  event; throughput delta SAV-off vs monitor vs drop; spoof-block
  accuracy under load.
- **Effort**: 1–2 days.
- **Licenses**: "SAV costs X% throughput in monitor mode at full
  table on hardware H" — a claim no other suite can even make.

### E7 — Codec micro-benchmarks (in-repo, CI-runnable)

- **Question**: encode/decode throughput of the hot codecs, tracked
  over time as regression gates.
- **Setup**: `criterion` benches in-crate: ZAPI message
  encode/decode, BGP UPDATE parse (the E1 replay corpus as fixtures
  — reuse the pinned MRT-derived samples), RTR PDU, policy filter
  evaluation. Added as `benches/` with a `cargo bench` target; a
  CI job (optional, D3) records but does not gate.
- **Metrics**: ns/op with criterion's statistics; tracked series.
- **Effort**: half a day; no containers needed.
- **Note**: adds `criterion` as a dev-dependency — an owner
  dependency decision (D2), consistent with the tokio-test-util
  precedent.

## D. Decision sheet (owner fills before the first run)

Recommendations are the orchestrator's, 2026-10-15; reasoning lives
in the chat record. The "Your decision" column stays the owner's.

| # | question | options | recommendation | Your decision |
|---|---|---|---|---|
| D1 | injector for E1/E2 | (a) exabgp replaying generated announce files; (b) small in-repo Rust MRT→BGP replayer (new dev tool, more control, more work); (c) both — (a) to start, (b) if (a) bottlenecks the injector itself | **(c), expecting (b) for published numbers.** Gate: measure injector headroom first — if exabgp (Python) cannot sustain ≥2× the SUT's ingestion rate, its numbers measure the injector, and the published runs switch to the in-repo replayer. | (c) accepted 2026-10-15 |
| D2 | criterion dev-dep for E7 | (a) yes, all crates that need it; (b) one crate first (zapi) | **(b)** — ratify the pattern on one crate (zapi: hottest codec, pinned fixtures exist), extend to the BGP UPDATE parser once the harness shape is proven. Same class as the tokio-test-util precedent: dev-dep, reviewable increment. | (b) accepted 2026-10-15 |
| D3 | bench job in CI | (a) nightly manual-dispatch only; (b) every push, non-gating; (c) skip CI, local only | **(a)** — shared runners have no CPU pinning, so CI numbers are trend-noise; nightly dispatch catches gross regressions (≥2×) and keeps the benches running. Comparative experiments (E1–E6) never run in CI; CI-benched numbers are descriptive-only and labeled `host=gh-runner`. | (a) accepted 2026-10-15 |
| D4 | host | (a) Linux box if available (best); (b) Mac Docker Desktop with `host=darwin-vm` labeling and the 2× unresolved rule | **(b) to build and debug, (a) for published ledger entries.** If no Linux host can be obtained (even a cheap pinned-cores VPS), publish under `darwin-vm` labels and honor the 2× rule. | (b)-dev/(a)-publish accepted 2026-10-15 |
| D5 | comparison set | (a) FRR only (the oracle; images cached); (b) FRR + BIRD (needs a bird image added to the cached set) | **(a) for the first ledger entries; extend to (b) for E1+E5 once the harness is proven.** BIRD matters most for E5 (memory, where BIRD is historically lean — the strongest test of the claim), but the FRR harness reuses everything the interop suite already pinned. | (a) now, (b) for E1+E5 later accepted 2026-10-15 |
| D6 | first claim to publish | (a) E1+E5 together (headline + memory); (b) E7 first (cheapest, no public comparative claim); (c) all at once when §R complete | **(a)** — one run session yields both (E5 rides E1's RSS logs), and they are exactly what the site/paper need to move from design facts to measured facts. E7 publishes alongside when ready; (c) delays everything to the slowest experiment. | (a) accepted 2026-10-15 |

## R. Results ledger (append-only)

- (empty — runs append here: `{date, experiment, host, versions
  {rouster, frr, bird, kernel}, feed checksum, runs, median, p95,
  raw-log path, notes}`)

- 2026-10-16 · E4+FIB-rate · host=darwin-vm (OrbStack 7.2.9-orbstack,
  macOS 27.0.1 host, linux/aarch64 VM, 18 CPUs, SUT pinned 4-11,
  injector 0-3, the third-container observer 12-17 — it shares the
  SUT's network namespace but NOT its cpuset pins) · versions: rouster
  binaries from the S14 round tree (`80cd7e7` over baseline `429ab18`;
  the only Rust delta vs the baseline is the sibling stream's in-flight
  interface hw_addr mirror — link-event/interface-dump paths, the
  route/RIB/netlink-install paths byte-identical, diff reviewed and
  disclosed here); harness `scripts/bench-e4-fib.sh` +
  `scripts/bench-observe.py` + `scripts/bench-ex-summarize.py`;
  FRR 10.2.2 side DERIVED from the ledgered FRR-full entry, not re-run
  (the pre-registered addendum above) · feed: same dump/pick/surgery
  (sha256 above), mrt-replay --limit B, unpaced, hold 90 · runs: 6 per
  size (1 warmup + 5 measured), sizes 1k / 10k / 100k · observation:
  the in-observer-container kernel-count loop (`ip route show proto
  186 | grep -c .`) at 39 / 38 / 28 rows/s for 1k / 10k / 100k (the
  dump's own RTNL cost is inside every measurement — disclosed; the
  wall is first-kernel-route → B−max(2, 0.5%) held, never a SUT
  self-report) · **B=1k: the whole install pass fits inside one dump
  gap — wall ≤ 24 ms median (upper bound), ≥ 42.1k routes/s (lower
  bound; observer-resolution limited, disclosed)** · **B=10k: wall
  median 0.089 s (p95 0.095, min 0.060) → 112.8k routes/s median
  (min-run 166.4k)** · **B=100k: wall median 0.692 s (p95 1.152, min
  0.612) → 144.6k routes/s median (min-run 163.3k)**; accepted
  1000/1000, 10000/10000, 99998/100000 on every run; malformed 0,
  rejected 0, netlink rcvbuf overruns 0 across all 18 runs · CPU
  (cumulative per run): rousterd median 0.64 s at 100k (≈6.4 µs per
  installed route; 0.07-0.08 s at 10k; ~0 at 1k), bgpd 0.50 s at 100k ·
  RSS pair at 100k: rousterd peak 25,556 KiB, bgpd peak 62,304 KiB
  (median; the transient ingest peak — the settled final is ≈44 MB,
  matching the E5 basis)
  · FRR side (derived): zebra 9.67 CPU-s / 1,126,490 routes =
  **116.5k routes per CPU-s** from its ledgered full-table run;
  Rouster's CPU-basis at the 100k cell = 100k / 0.64 CPU-s =
  **156k routes per CPU-s** → 1.34× — sub-2×, so the comparative
  direction stays unresolved under §F's darwin-vm rule (both
  directions published); the per-size descriptive walls/rates on this
  rig are licensed · raw: `target/bench-logs/e4-20261016T151635Z/`
  (per-run poll.csv at the observer cadence, observe.csv, SUT logs,
  summary.json per size; the resolution-limited first pass
  `e4-20261016T150703Z` kept as the host-side-cadence comparison) ·
  notes: the measured pass is the F8 pipelined route_replace_batch
  reconcile overlapping the ingest tail (at these sizes bgpd's EOR
  completes before the kernel pass ends — the 100k wall total from
  injector launch is 3.9 s median, of which 0.69 s is the kernel-count
  pass); wall_total medians 2.54 / 2.61 / 3.90 s for 1k / 10k / 100k.
  No verdict prose.

- 2026-10-16 · allocator-share measurement (the PERF-M1/M3 escalated
  owner decision, resolved to a recommendation — NOT a dep adoption)
  · method per the escalation: the smaps rollups' anonymous-mapping
  share vs the RSS-growth-curve fit against the per-structure census ·
  inputs (all this tree, same rig): three clean bench-profile runs
  (10k/50k/100k, `profile-20261016T1459{24,50}Z` + `145752Z`), the
  bgpd mem-census at 100k (`mem-logs/census-20261016T150016Z`), the
  rousterd mem-census at 100k (`cpu-logs/census-20261016T150057Z`);
  the fold: `target/bench-logs/allocator-20261016T1516/analysis.txt` ·
  smaps at 100k final: the anonymous arena IS the table memory — bgpd
  44,104/44,164 KB (99.9%), rousterd 23,080/23,128 KB (99.8%); no
  file-backed or mapping growth · growth fit (LSQ over the three
  sizes): bgpd **428.6 B/prefix marginal** (intercept 569 KiB),
  rousterd **201.4 B/prefix marginal** (intercept 734 KiB) · census
  structure on this tree: bgpd = interned attrs 90.7 B/pfx (measured
  deep; 16,621 distinct tuples, per-route attr allocs ≈0) + keyed-map
  inline ≈157 B/pfx (M3's measured 165 scaled Route 56→48 — an
  estimate, disclosed) ≈ **248 B/pfx** → residual **≈181 B/pfx = 42%
  of the marginal 429** (46% against the census-build marginal);
  rousterd = node-model floor 114 B/pfx (tables 46 + programmed 68,
  full-fill) to ≈165 B/pfx at realistic 69% B-tree fill → residual
  **36-87 B/pfx = 18-43%** (fill-model sensitivity disclosed; 29%
  against the ledger's 233 B/pfx at 100k) · the 15% bar (the
  escalation's own rule): speaker 67 B/pfx, core 34 B/pfx — **both
  residuals clear it** (speaker decisively; core at the bar's edge
  under the most structure-favorable model), so the outcome is the
  evaluation branch, not "not worth the dependency" · evaluation
  (owner decision, nothing adopted): (a) mimalloc — one crate, no
  transitive deps, `#[global_allocator]`, musl-compatible, ~x00 KB
  binary cost; per-thread heaps fit the multi-core design; typical
  small-object RSS recovery 10-20%; (b) tikv-jemallocator — heavier
  dep tree (C build via jemalloc-sys), background-purge threads
  optional, the least-tested musl path; (c) decline — the current
  numbers already lead FRR 2.1×/2.27× on memory and the residual is
  an UPPER bound (transients + node over-fill + unmodeled surfaces
  share it; a swap recovers only the allocator-proper part, plausibly
  ~50-100 B/pfx of the speaker's 181) · recommendation: if the owner
  wants the speaker floor pushed, ratify a time-boxed mimalloc A/B on
  bgpd only (the D2 one-crate-first pattern), receipt-gated per
  §R/PERF-PLAN (±5% on every other metric); decline on any regression
  or <5% recovery. No verdict prose.

- 2026-10-16 · E2+churn matched comparison (10% of a 100k table
  flapped ×10 rounds, identical injector both sides) · host=darwin-vm
  (same rig: SUT pinned 4-11, injector 0-3, the kernel-count observer
  loop 12-17 in a third container sharing the SUT netns) · versions:
  Rouster binaries as in the E4 entry above (tree `80cd7e7` over
  `429ab18`; perf paths byte-identical, disclosed there); FRR 10.2.2;
  harness `scripts/bench-e2-churn.sh` + `scripts/bench-flap.py` (the
  flap-capable injector: the mrt-replay announce content — see the
  addendum above — with protocol-level withdraw/reannounce on the
  announcing session; SAME tool, SAME bytes, SAME schedule on both
  SUTs per §F) · feed: `announce-100k.announce` (sha256
  6c9f4f7d7369cb25a6f4c35fc64d0da481b7116cb7346597c26f0484c45d7ced,
  the bench-mrt2announce derivative of the pinned dump above), 100k
  routes announced in ~2.2-2.4k UPDATEs, subset = every 10th prefix
  (10,000), 10 rounds, 2 s inter-burst gaps · runs: 6+6 (1 warmup + 5
  measured each) · observation: the kernel-count loop at ~7 rows/s
  symmetric (its dump cost rides both sides equally); the SUT-own
  count basis is rouster's status file (1 s refresh cadence, the SUT's
  own surface) vs FRR's live vtysh — the kernel basis is the
  symmetric one and leads the table · **per-round reconvergence
  (reannounce-done → kernel count restored): Rouster median 0.330 s
  (p95 0.446) vs FRR 10.2.2 median 0.235 s (p95 0.327) — FRR ahead
  1.40×, sub-2×, unresolved under §F's darwin-vm rule (both
  directions published)** · SUT-own-count basis: Rouster 0.252 s
  (0.620) vs FRR 0.170 s (0.293) — same direction, same disclosure ·
  full round wall (withdraw-start → restored): Rouster 2.317 s
  (2.686) vs FRR 2.227 s (2.357) — parity within noise · withdraw
  trough exact on both sides every round (Rouster 99,998 → 89,998;
  FRR main Totals 100,001 → 90,001; 10,000 prefixes withdrawn and
  restored ×10 rounds ×5 measured runs ×2 sides) · storm CPU
  (steady → rounds-done, ~80 s window): speaker Rouster 0.81 s vs
  FRR bgpd 1.16 s (Rouster 1.43× fewer); core Rouster 1.26 s vs FRR
  zebra 2.24 s (1.78× fewer) — both sub-2×, unresolved · session
  survival: the injector's own timeline — zero NOTIFICATION, zero
  aborts, FLAP-LINGER-END reached on all 12 runs (FRR's final-vtysh
  "Active" state is the post-linger injector close, a capture-timing
  artifact disclosed here); malformed 0 / rejected 0 on every run ·
  raw: `target/bench-logs/e2-20261016T152650Z/` (rouster) +
  `e2-20261016T153522Z/` (frr) · notes: the pre-registered rate sweep
  (100–1000 cycles/s) and the full-table cell stay deferred per the
  addendum; the round shape at 100k is this entry. No verdict prose.

- 2026-10-16 · E3+sessions matched grid (N ∈ {10, 50, 100} × SUT cores
  ∈ {1, 2, 4}, both sides) · host=darwin-vm (same rig; SUT cpuset 4 /
  4-5 / 4-7 per cell, the injector fleet 0-3, one container per
  session from the `docker/bench/Dockerfile.mrt-replay` fleet image,
  per-session table = the feed's first 100 prefixes) · versions: as
  the E4/E2 entries above (tree `80cd7e7`+ over `429ab18`; FRR
  10.2.2) · release: the fleet's containers run waiter commands and
  are released by a shared GO file (all waiters armed before the
  release epoch; actual start spread ≤ 29 ms median in every cell —
  recorded per run) · runs: 6 per cell (1 warmup + 5 measured), 108
  runs total · **failures 0 and SUT-side Established cross-count = N
  on every run of every cell, both sides** · wall first-connect →
  all-N Established (medians):
  | N | cores | Rouster | FRR 10.2.2 |
  |---|---|---|---|
  | 10 | 1 / 2 / 4 | 4 / 5 / 4 ms | 4 / 4 / 4 ms |
  | 50 | 1 / 2 / 4 | 35 / 29 / 27 ms | 19 / 20 / 18 ms |
  | 100 | 1 | 93 ms (1,072 sess/s) | 41 ms (2,441 sess/s) |
  | 100 | 2 | 167 ms (600 sess/s) | 39 ms (2,544 sess/s) |
  | 100 | 4 | 157 ms (636 sess/s) | 41 ms (2,428 sess/s) |
  both directions published: **FRR ahead at N=100 by 2.3× (1 core) to
  4.3× (2 cores) — beyond the 2× bar, resolved under §F's darwin-vm
  rule; ahead ~1.5× (sub-2×, unresolved) at N=50; parity at N=10** ·
  SUT speaker CPU at N=100: Rouster 0.57-0.60 s vs FRR 0.05 s
  (~5.7 ms vs ~0.5 ms CPU per establishment; core CPU 0.01 s both) ·
  the multi-core architecture claim's own test outcome at this grid:
  neither side's establishment wall improves with cores at any N —
  Rouster's c1 cell is its FASTEST at N=100 (93 ms vs 157-167 ms) —
  so establishment at N ≤ 100 on this rig is not a core-count-bound
  workload; the claim remains unproven by this grid (disclosed, no
  verdict prose) · new finding **F10** (escalated, not diagnosed
  here): rouster bgpd's per-session establishment cost is ~11× FRR's
  CPU at N=100 and its throughput degrades with N (2,286/s at 10 →
  636/s at 100 on c4) while FRR stays flat (~2,400-2,800/s) —
  candidate causes for a PERF stream: per-session task/allocator
  setup, accept-loop serialization, or per-peer config recompute;
  the harness gives the reproducible cell shape · raw:
  `target/bench-logs/e3-20261016T160019Z/` (rouster) +
  `e3-20261016T161507Z/` (frr) · harness disclosure: the first grid
  attempt (aborted mid-run, rouster N=10/50 cells complete) measured
  a docker-exec launch loop's skew as the wall at N ≥ 50 (diagnosed
  from start_spread == wall; fixed by the GO-file release, commit
  `794960b`); the aborted attempt's artifacts stay on disk at
  `e3-20261016T154618Z/` (superseded, not cited) — all published
  numbers are from the fixed harness.

- 2026-10-15 · E1+FRR-full · host=darwin-vm (OrbStack 7.2.9-orbstack,
  macOS 27.0.1 host, linux/aarch64 VM, 18 CPUs, SUT pinned 4-11,
  injector 0-3) · versions: FRR 10.2.2 (`frr-testbed:10.2.2`), harness
  rouster repo @1aa88be · feed: route-views2 rib.20261015.0400.bz2
  (sha256 930bcfce34b31ca48c52d7c9d8f8081db1ff8b9ee8ec7d8db7e4ddd023153d5b),
  1,126,490 IPv4-unicast prefixes, lowest-peer-index path per prefix,
  NEXT_HOP rewritten + injector AS 65412 prepended (mrt-replay) ·
  runs: 6 (1 warmup + 5 measured) · injector: in-repo `mrt-replay`
  (D1(c) switch; exabgp disqualified — ~36 msg/s sustained,
  deterministic hold-time session death in bulk API mode) ·
  **wall first-UPDATE→main-table-complete: median 30.36 s,
  p95 30.42 s (≈37.1k routes/s; ~33.4k UPDATE msg/s)** · CPU s:
  bgpd median 11.03 (p95 11.07), zebra 9.67 (9.85), injector 1.28 ·
  RSS peak: bgpd 1,022,508 KiB (median), zebra 606,272 KiB; final:
  bgpd 1,022,440, zebra 593,908 · E5 (this run): bgpd RSS
  11,408→1,022,508 KiB ≈ **897 B/prefix**; zebra 7,976→593,908 ≈
  **519 B/prefix** · raw: `target/bench-logs/frr-20261015T062832Z/`
  · notes: wall anchored at the injector's first UPDATE send and
  main-table = zebra `show ip route summary` Totals (includes kernel
  FIB install completion); FRR json pfxRcd settles at feed−9
  (0.0008 %, bgpd log clean at info level, cause unattributed);
  556,132 UPDATE messages delivered in 5.01 s (injector sustained
  ≈225k routes/s, CPU 1.28 s — the D1 gate: injector headroom
  ≈3,500× FRR's own consumption); EOR-then-linger keeps the session
  up so the table survives measurement.

- 2026-10-15 · E7+zapi-codec · host=macbook-native (macOS 27.0.1,
  aarch64, quiet-machine criterion run; NOT darwin-vm — no containers)
  · versions: rouster repo @<this commit>, criterion 0.5.1 (crates/zapi
  dev-dependency, D2's one-crate-first pattern) · corpus: the Z1
  pinned wire fixtures (`crates/zapi/tests/fixtures/{staticd,bgpd,
  ospfd}-10.2.2.log`, 15/23/5 captured messages; non-empty bodies) ·
  runs: criterion defaults (100 samples, 3 s warmup) ·
  **decode (full-corpus pass): staticd median 147.4 ns, bgpd 33.5 ns,
  ospfd 6.0 ns** · **encode_body (full-corpus pass): staticd 324 ns,
  bgpd 357 ns, ospfd 57 ns** · raw: `target/criterion/` +
  `cargo bench -p zapi` rerunnable · notes: `benches/zapi_codec.rs`
  asserts nothing — descriptive micro numbers only; the byte-exact
  ground truth stays in `tests/golden.rs`. The D3 nightly CI dispatch
  job is deliberately NOT wired (owner requests it separately).

- 2026-10-15 · E1+E5 Rouster 10k-slice · host=darwin-vm (OrbStack
  7.2.9-orbstack, macOS 27.0.1 host, SUT pinned 4-11, injector 0-3)
  · versions: rouster repo @775fdde (rousterd+bgpd, aarch64 musl) ·
  feed: same dump/pick/surgery as the FRR-full entry; FIRST 10,000
  prefixes (mrt-replay --limit 10000) · runs: 6 (1 warmup + 5
  measured) · injector paced 120 msg/s, hold-time 900 (the F7
  mitigation — see notes; ≥2× headroom holds: injector CPU median
  0.22 s vs SUT 593.5 s) · **wall first-UPDATE→main-table-complete:
  median 598.3 s, p95 608.6 s (≈16.7 routes/s average; bgpd CPU
  median 593.5 s = CPU-bound on one core for the whole run)**
  · CPU s: rousterd 0.80, injector 0.22 · RSS: bgpd 2,072 → peak
  18,524 KiB (median), rousterd 2,760 → 11,016 · **E5: bgpd
  ≈1,573 B/prefix at 10k (2,072→~17,800; ≈1,626 B/prefix at the 5k
  mark), rousterd ≈765 B/prefix** · main-table finals 9,985–10,000
  (0–15 prefixes unaccounted per run, bgpd log clean) · raw:
  `target/bench-logs/rouster-20261015T080356Z/` · notes: the full
  1,126,490-prefix protocol was NOT COMPLETED — bgpd's
  LocRib::recompute is O(table) per UPDATE (O(n²) load; profile +
  decay curve in the program report; projected weeks per run at full
  table); the deepest completed point is 14.6k prefixes at ~1.85/s
  (s1-20k-v2 run-1 partial, 36 min). Rouster-side runs used the
  pacing+hold mitigations for finding F7 (session-loop read
  cancellation under a select! race; clean-wire tee-proxy evidence)
  — disclosed as transport shape, identical on the FRR matched runs.

- 2026-10-15 · E1+E5 matched comparison, 10k slice, identical
  injector (120 msg/s pace, hold 900, same feed) · host=darwin-vm ·
  per §F both directions, versions pinned above · runs 6+6:
  | metric (10k slice) | Rouster @775fdde | FRR 10.2.2 |
  |---|---|---|
  | wall median (first-UPDATE→main complete) | 598.3 s | 44.3 s |
  | wall p95 | 608.6 s | 44.4 s |
  | speaker CPU s (median) | 593.5 (bgpd) | 0.58 (bgpd) |
  | zebra-side CPU s (median) | 0.80 (rousterd) | 0.42 (zebra) |
  | speaker RSS Δ (empty→peak, KiB) | 2,072→18,524 | 11,436→20,416 |
  | zebra-side RSS Δ (KiB) | 2,760→11,016 | 8,060→13,432 |
  | accepted prefixes | 9,985–10,000 | 10,000/10,000 |
  | bytes/prefix (speaker, 10k) | ≈1,573 | ≈898 |
  | bytes/prefix (zebra-side, 10k) | ≈765 | ≈537 |
  notes: FRR's 44.3 s is the injector's pacing floor (its daemons are
  idle — 0.58 s + 0.42 s CPU; FRR's unpaced full-table capacity is
  the separate entry above: 1,126,490 prefixes, median 30.36 s);
  Rouster's 598.3 s is SUT-bound (CPU-pegged, the O(n²) finding).
  Cross-side deltas exceed 2× on wall/CPU; per §F's darwin-vm rule
  sub-2× deltas stay unresolved — none here are. No verdicts; the
  numbers and conditions are the deliverable.

- 2026-10-15 · E1+E5 Rouster full-table, POST-FIX (F1+F7+F5, commit
  `47ef0ee`) · host=darwin-vm (OrbStack, same rig: SUT pinned 4-11,
  injector 0-3) · versions: rouster repo @47ef0ee · feed: identical
  dump/pick/surgery (sha256 above), full 1,126,490 prefixes ·
  runs: 6 (1 warmup + 5 measured), UNPACED, hold-time 90 (the F7
  mitigation — pacing 120 msg/s + hold 900 — is retired with the
  fix; this is the FRR-shaped protocol) · **BGP-level wall
  first-UPDATE→EOR: median 4.73 s, p95 4.87 s (556,132 UPDATEs ≈
  118k msg/s; ≈238k routes/s) — malformed 0, rejected 0 on every
  run** (the F7 receipt: the pre-fix reader desynced at 120 msg/s
  paced) · CPU s: bgpd median 9.14 (p95 9.28), rousterd median
  235.08, injector 1.11 · **wall first-UPDATE→main-table-complete:
  median 247.8 s, p95 284.1 s — dominated by the FIB programming
  path (new finding F8: rousterd programs ~1.12M routes at ≈4.8k
  routes/s where FRR zebra's ledgered cost is 9.67 CPU-s; 235 s of
  the 248 s wall is rousterd CPU)** · RSS: bgpd 1,972 → final
  1,851,468 KiB, HWM 2,120,784 (median) · **E5: bgpd ≈1,681 B/prefix
  final (≈1,926 peak), rousterd ≈922 B/prefix final** (stage-wise
  speaker marks are unusable this run: bgpd finishes the full table
  in 4.7 s while the main-table poll marks run for minutes — the
  E5 deltas above use empty→final/HWM) · main-table peaks
  1,120,924–1,126,481 across runs (3/5 measured runs reach feed−9 =
  1,126,481; two plateau 0.1–0.5 % short with rousterd CPU still
  pegged at poll end — disclosed, unattributed; candidate: poll
  window vs programming tail) · raw:
  `target/bench-logs/rouster-20261015T094736Z/` (summary mirrored
  at away/2026-10-15/bench/e1-rerun-summary.json) · notes: the
  FRR-side comparison numbers are the earlier entries (same feed,
  same rig): end-to-end wall 30.36 s (FRR) vs 247.8 s (Rouster) —
  the >2× delta is resolved and attributed to F8, the kernel-
  programming path, while the speaker-level CPU comparison
  (bgpd 9.14 vs 11.03 CPU-s) is sub-2× and stays unresolved under
  §F's darwin-vm rule. No verdict prose; F8 goes to the owner
  decision list.

- 2026-10-15/16 · E1+E5 Rouster full-table, POST-F8 (commit
  `5afbba6`: pipelined route programming, dirty-key reconcile, tick
  Delay) · host=darwin-vm (same rig, same feed, sha256 above) ·
  runs: 6 (1 warmup + 5 measured), unpaced, hold-time 90 ·
  **wall first-UPDATE→main-table-complete: median 17.1 s, p95 17.1 s,
  min 17.0 s (3 of 5 measured runs reached main = feed−9 =
  1,126,481 — full table in-kernel every run that completed its
  poll; malformed 0, rejected 0 on all six runs)** · EOR wall
  median 6.07 s (p95 6.38) — higher than the pre-F8 4.73 s because
  rousterd's pipelined installs now overlap bgpd's ingest instead
  of queueing behind it; total SUT CPU is what dropped: **bgpd
  10.37 s + rousterd 10.90 s = 21.3 CPU-s (pre-F8: 9.14 + 235.08;
  FRR's ledgered pair: 11.03 + 9.67 = 20.7)** · rousterd programming
  rate ≈65k routes/s effective (was ≈4.8k) · **E5: bgpd ≈1,679
  B/prefix final (RSS 1,848,588 KiB median), rousterd ≈784 B/prefix
  (865,480 KiB)** · raw: `target/bench-logs/rouster-20261015T141901Z/`
  (summary mirrored at away/2026-10-15/bench/e1-f8-summary.json) ·
  notes (disclosed): measured-run wall statistics cover the three
  runs whose main-table poll completed — runs 4 and 5 lost their
  poll side (run 4: zero samples, run 5: stopped at 625,462) with
  the SUT otherwise healthy; hypothesis: the poll's netlink
  route-dump (`ip route` via docker exec) starves under the 512-
  in-flight install storm on a 17 s run (dump-vs-churn RTNL
  contention). Harness follow-up, not a SUT finding; the harness
  should poll the rousterd status socket instead of dumping the
  kernel table. Cross-side: end-to-end 17.1 s vs FRR's 30.36 s is a
  1.78× delta — sub-2×, so even this stays unresolved for
  comparative claims under §F's darwin-vm rule; the descriptive
  claim ("full table in-kernel in 17.1 s median on this rig") is
  licensed. No verdict prose.

- 2026-10-16 · P0-b harness fix — E1 poll reliability (PERF-PLAN
  Phase 0; harness-only, no SUT change, no benchmark numbers change —
  the v1.0.0-era figures above stand) · host=darwin-vm (same rig:
  OrbStack, SUT pinned 4-11, injector 0-3) · harness commits 8c3eec3
  +6279afd+9131271 · diagnosis (corrects the prior entry's
  hypothesis): the "lost poll side" was NOT observer starvation — the
  poll reads the rousterd status file, not the kernel table, and the
  instrumented poll's docker-exec legs measured 33-39 ms median
  (max 101 ms) straight through the install storm (6-run pre-fix
  session, raw: `target/bench-logs/rouster-20261016T073357Z/`,
  which wedged 0/6 — the defect is a race; the baseline session
  wedged 3/6). The wedged baseline runs (raw:
  `target/bench-logs/rouster-20261015T141901Z/` run-1/5/6) each end
  at exactly one `netlink socket buffer full` WARN (netlink-proto
  0.12.2 framed ENOBUFS; zero occurrences in the healthy runs), with
  rousterd CPU flat, installs stopped mid-table, and the status file
  frozen (run-5's stayed at startup content — prefixes 0 — while the
  kernel held 629,228 bgp routes at teardown; run-6's froze at
  625,462 with 860,548 in-kernel). Mechanism — new finding **F9**
  (SUT-side, escalated to the owner list): rousterd's netlink socket
  subscribes to the route multicast groups, so each of the ~1.12M
  pipelined installs echoes a notification back to the same socket;
  when the daemon's single netlink connection task is starved >~25 ms
  under the storm, the default rcvbuf (`net.core.rmem_default`
  212992 B) overruns and the kernel drops datagrams — including ACKs
  for in-flight installs; netlink-proto 0.12.2 request futures carry
  no timeout, so each dropped ACK hangs its install future, the zapi
  drain arm of rousterd's main loop never returns (installs, the
  reconcile tick, and the status refresh all stop), and the poll
  faithfully reports the frozen file until timeout. The prior entry's
  "SUT otherwise healthy" note is corrected by this entry: the SUT
  was wedged. Fix (harness-side, symmetric on both SUT starters per
  §F): SUT containers run with `net.core.rmem_default=32 MiB`
  (`rmem_max=64 MiB`) — ~2 s of starvation slack vs ~25 ms
  (`BENCH_SUT_RMEM=0` restores the prior rig for A/B); the poll CSV
  carries a monotonic per-iteration timestamp and per-call wall
  times; a post-EOR stall guard (`--stall-after 180`) fails a wedged
  run fast as POLL-STALL instead of burning the timeout;
  bench-summarize surfaces `netlink_rcvbuf_overruns` per run; rig
  placement (net/subnet/IPs) is env-overridable for concurrent
  sibling streams (defaults unchanged; the pre-fix session ran on
  bench-net-p0 172.31.254.0/24 with SUT 12-16/injector 17 while
  PERF-M1 held the default placement) · **receipt: 6/6 complete-poll
  E1 runs on the fixed harness** — all six reach 1,126,481 (feed−9),
  external wall 17.01-17.10 s, 0 rcvbuf overruns (raw:
  `target/bench-logs/rouster-20261016T074332Z/`) · remaining,
  escalated: F9's SUT-side fix (an ACK timeout or overrun-triggered
  resync in the netlink install path — the harness fix removes the
  trigger, not the SUT's fragility to lost ACKs); optionally, the 10 s
  status-refresh cadence makes the per-second poll series stepwise
  (0 → ~660k → 1.126M on a 17 s run) — adequate for completion
  detection, coarse for ingestion curves. No verdict prose.

- 2026-10-16 · P0-c profiling rig available · `scripts/bench-profile.sh`
  (`rouster|frr <raw-mrt> [limit] [interval]`, commit b4f17d2) — the
  no-deps path, chosen and disclosed: per-daemon `/proc/<pid>/smaps`
  per-mapping Rss/Pss rollups + VmRSS/VmHWM + CPU jiffies sampled at
  fixed marks (empty → 1 Hz series → final-after-settle) around a
  pinned N-prefix ingest (default the 100k slice); artifacts under
  `target/bench-logs/profile-<ts>/` including a PROTOCOL.txt pinning
  repo head, image, feed sha256, binary sha256s, kernel, and CPU
  pins — an optimization stream runs it before and after a change
  and compares `rollup.tsv`. Validated clean on a 100k rouster slice:
  99,998 routes in-kernel, both daemons' rollups show the anonymous
  arena dominant (bgpd 48.5 MB, rousterd 78.8 MB final RSS; raw:
  `target/bench-logs/profile-20261016T080132Z/`) · limits disclosed:
  smaps names the memory consumer per mapping but attributes no
  allocation sites; the deeper options stay owner decisions (a
  rousterd SIGQUIT-style allocation census behind a feature flag —
  bgpd's counterpart landed as PERF-M1's feature-gated mem-census
  @7307053 with its own receipt runner — and a pprof/flamegraph
  sampling build, a profiler dependency). CPU-side naming remains
  with the E7 criterion micros until an owner-approved profiler
  lands.

## Where things live (conventions)

- Scripts: `scripts/bench-<E#>-<name>.sh` (the smoke-suite shape;
  self-cleaning containers, logs under `target/bench-logs/`).
- Configs both sides: `docker/bench/` (committed; a comparison is
  reproducible only if both configs are in the repo).
- Raw artifacts: `target/bench-logs/<E#>-<ts>/` (gitignored),
  summarized into §R; the summary cites the artifact dir.
- When a result lands, the campaign fact sheet gains a measured
  section (the "no `fast` without benchmarks" rule in
  FACTS §8b/plan §1 lifts for exactly the measured dimensions).
