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

- 2026-10-16 · allocator A/B (mimalloc on bgpd, the S14-b
  recommendation, owner-ratified "proceed") · host=darwin-vm (same
  OrbStack VM/kernel as every §R entry; ISOLATED placement while
  sibling stream S15-a held the default: net bench-net-s15b
  172.31.253.0/24, SUT cpus 12-16, injector cpu 17, container prefix
  ab-s15b-; §F's same-host/same-engine holds inside the comparison —
  both sides same rig, same feed, same injector) · versions: rouster
  tree `ea6f5d2` (= baseline `a6c11bc` + this stream's alloc-mimalloc
  manifest lines `48d2124` + sibling S15-a's env-gated F10
  establishment instrumentation `ea6f5d2`, landed in-tree before the
  snapshot and carried IDENTICALLY by both sides, not activated by
  this protocol — no env set; S15-a's later rib change `147a0cd` is
  NOT in the tree; the sibling's src lane disclosed per the S14
  precedent); binaries CONTAINER-built in rust:alpine (rustc 1.99.1,
  native aarch64-unknown-linux-musl, both sides same compiler and
  flags — the host musl cross-build has no C toolchain for
  libmimalloc-sys's cc build, so the container is the reproducible
  path, disclosed); side B = the same snapshot + the 3-line
  cfg-gated `#[global_allocator]` activation point applied to the
  SNAPSHOT COPY's `crates/bgpd/src/bin/bgpd.rs` (hook.diff in the
  artifact dir; the repo's bgpd src untouched — S15-a's lane); side A
  = the same snapshot, feature off (the hook cfg-stripped: A/B differ
  by exactly the allocator + dep); mimalloc 0.1.52 /
  libmimalloc-sys 0.1.49 (mimalloc v3.3.2, DEFAULT options, no env
  tuning); lockfile delta additive (mimalloc + libmimalloc-sys + cc
  1.8.0 + find-msvc-tools + shlex, all build-time) · harness
  `scripts/bench-alloc-ab.sh` — the E1 100k protocol verbatim
  (mrt-replay unpaced hold 90, P0-b rcvbuf sysctls on, bench-poll
  observer, bench-summarize per side, the A/B fold) · feed: the
  pinned dump (sha256 above), --limit 100000 · runs: 6+6 (1 warmup +
  5 measured per side, warmups first then alternating) · receipts:
  MIMALLOC_VERBOSE=1 in the daemon env on BOTH sides every run —
  side B's bgpd log carries the mimalloc init banner all 6 runs,
  side A's carries none (the negative control; the env var is inert
  under the default allocator); binary symbol checks (B: 6 mimalloc
  strings + mi_malloc; A: zero of either); the NOISE CONTROL:
  rousterd is byte-identical on both sides and still shows a -13.85%
  CPU delta between sides — the rig's CPU-delta noise scale at this
  placement is ~10-14%, the scale the bgpd CPU delta below must be
  read against · accepted 99,998/100,000 every run both sides;
  malformed 0 / rejected 0 / rcvbuf overruns 0 on all 12 ·
  | metric (median [p95]) | A: system | B: mimalloc | B vs A |
  |---|---|---|---|
  | speaker B/prefix (empty→final) | **451.88 [472.4]** | 714.73 [947.0] | **-58.2% (regression)** |
  | bgpd empty RSS KiB | 2,072 [2,112] | 8,156 [8,167] | +6.1 MB eager floor |
  | bgpd final RSS KiB | 46,232 [48,181] | 77,952 [100,629] | +68.6% |
  | bgpd HWM KiB | 78,720 [80,500] | 90,232 [96,401] | +14.6% |
  | bgpd CPU s | 0.46 [0.52] | 0.41 [0.44] | -10.9% (noise-scale, see control) |
  | wall first-UPDATE→complete s | 1.859 [5.248] | 1.882 [1.979] | +1.2% |
  | wall EOR (BGP-level) s | 0.267 [0.343] | 0.246 [0.277] | -7.9% |
  · gate (pre-registered): ADOPT needs ≥5% B/prefix recovery with no
  wall/CPU regression >5% — B/prefix recovery is **-58.2%**, so the
  swap is **DECLINED by the receipt gate**; the secondary legs hold
  (wall +1.2%, EOR -7.9%, CPU -10.9% = within the noise control's
  scale) but the primary fails decisively · findings: with default
  options on this single-peer burst-ingest shape mimalloc costs more
  than it packs — a +6.1 MB eager-commit floor at startup (per-thread
  heaps; the banner's eager-commit options) and retained small-object
  bins at settle (final +68.6%; B-side run spread 454.8-903.1 B/pfx
  with one run releasing to A-parity after purge — retention timing
  variance, disclosed); the S14-b "plausibly 10-20% small-object RSS
  recovery" estimate is refuted on this rig/shape; the M4 residual
  (~185 B/pfx decode/drain transients + bins) is cheaper held under
  the system allocator · side A independently re-validates the M3-era
  449 B/pfx receipt in a different build environment (451.88 median,
  +0.6%) · decision state: the feature stays OPT-IN (default OFF,
  unchanged); the src-side hook stays unlanded (quoted in the
  artifact for reproduction); mimalloc env tuning (purge delay /
  eager-commit off) would be a different, unpre-registered experiment
  — named here only as the path a future revisit would have to take ·
  raw: `target/bench-logs/alloc-ab-20261016T222705Z/` (PROTOCOL.txt
  with the hook diff + binary sha256s, verify/ banners + symbol
  counts, per-run poll.csv + alloc-verify.txt, ab-summary.json) ·
  harness bring-up disclosed: `alloc-ab-20261016T222036Z` was the
  protocol-validation pass with a copy-order defect (both sides ran
  the feature binary — diagnosed from BOTH banners showing mimalloc
  init, fixed before any measured run; kept as the identical-binary
  spread datum: 819.6 vs 861.6 B/pfx ≈ 4.9% single-run noise);
  earlier aborted attempts `alloc-ab-20261016T221648Z` (relative
  docker mount path) and `alloc-ab-20261016T221727Z` (rust:alpine
  rust-lld proc-macro links need the native lib dirs on the search
  path — fixed by passing -L/usr/lib and gcc's libgcc dir) are
  superseded, not cited · wall p95 note: side A's 5.248 p95 is one
  run at 3.88 s — completion-detection quantization against
  rousterd's 10 s status refresh (the EOR-level wall is the finer
  ingest metric, both published).

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

- 2026-10-19 · E1 matrix on BARE METAL (the plan §11.1 controlled
  host; the rewrite's E2-configB close-out) · host=dgx-spark-1
  (NVIDIA DGX Spark, GB10, 20 aarch64 cores in two L3 clusters:
  cpus 5-9 @3900MHz and 15-19 @3978-4004MHz are the fast pairs;
  Ubuntu 24.04.3, docker 28.3.3; governor performance, SUSTAINED
  2964 MHz sampled on the SUT cores under load vs the 3.9-4.0 rating;
  no sudo → netlink rcvbuf at kernel default 212992, carried by the
  SUT-side F9 hardening with ZERO rcvbuf overruns and zero
  resync/ack-timeout lines in every rousterd log) · rig: bench-net
  172.31.255.0/24, SUT .20 on ONE L3 cluster (cpus 5-9), injector
  .10 on 0-3, host-side observer; binaries = the same
  aarch64-musl static builds as the 2026-10-19 hybrid receipt (tree
  5fa1856; BENCH_BIN_DIR prebuilts) · feed: the pinned dump (sha256
  above), full 1,126,490, same surgery · 6 runs per leg (1 warmup +
  5 measured) · **single-cluster matrix: A (frr/frr): wall 30.556 s
  med (p95 30.60), bgpd CPU 13.57, zebra CPU 11.48, speaker
  (1,022,132−10,476 KiB) = 919.5 B/pfx, core (592,748−7,300) =
  532.8 B/pfx. B (frr bgpd+mgmtd on rousterd): wall 30.515, bgpd
  13.30, rousterd 16.96, speaker 919.3, core 229.4. D
  (rouster/rousterd): wall 13.522 (p95 13.55), bgpd 9.37, rousterd
  17.56, speaker (501,348−1,708) = 453.1 B/pfx, core (254,792−2,228)
  = 229.4. All runs reach the full table (A basis 1,126,484 zebra
  summary; B/D 1,126,481 = feed−9), 0 overruns.** · **D/A wall =
  2.26× on this host (darwin-vm: 3.79×). B ≡ A on wall on BOTH
  platforms (30.515 vs 30.556 here; 31.07 vs 30.36 there) while B's
  core memory = D's core memory (229.4 vs 532.8 = 2.32×) — the
  stage attribution REPLICATES. Memory reproduces cross-platform to
  ≤0.1% (919/533/229) except D's speaker (453 vs 420-428 on the VM,
  +6-8%, disclosed).** · split-L3 finding (first pass, SUT on
  5-9,15-19): D wall 17.513 / rousterd CPU 25.84 / bgpd 13.46; A
  30.533/13.10/11.18; B 30.539 — collapsing the SUT to one cluster
  cut D's wall 23% and rousterd's CPU 32% while FRR moved ~nothing:
  the async daemons are placement-sensitive on this host, the C
  daemons are not. Residual D-core CPU factor vs the VM (17.56 vs
  6.95 = 2.5×): ~1.35× effective clock (measured) + ~1.9× named
  candidates (cluster L3/TLB geometry, allocator) — disclosed, not
  decomposed further. CPU-parity note: A pair 25.05 CPU-s vs D 26.93
  here (the wall advantage is overlap, while on the VM D also spent
  less CPU — both directions published) · harness:
  scripts/bench-e1-ingest.sh (BENCH_BIN_DIR/BENCH_SUT_CPUS/
  BENCH_SUT_RMEM=0) · raw: dgx-spark-1:~/rouster-bench/target/
  bench-logs/{frr,hybrid,rouster}-20261019T*; receipts mirrored at
  away/2026-10-19/bench/dgx-e1/ (PROTOCOL.md + summaries + median
  poll.csvs + MHz samples + governor). No verdict prose.

- 2026-10-19 · E2+E3+E7+E4 on the bare-metal host · host=dgx-spark-1
  (rig/platform identical to the 2026-10-19 bare-metal E1 entry: SUT
  cpus 5-9 single L3 cluster, injector 0-3, observers 10-14 / host,
  rmem at kernel default, 0 overruns on every run; binaries tree
  5fa1856) · **E2 churn (both sides ×6): Rouster reconvergence
  0.285 s med (p95 0.387) vs FRR 0.130 s (p95 0.206) — FRR ahead
  2.19× (darwin-vm: 1.40×); round wall 2.496 vs 2.316; storm CPU
  speaker 1.27 vs 2.04 (Rouster fewer), core 3.17 vs 2.90; 10/10
  rounds, 0 malformed.** · **E3 grid (both sides ×9 cells ×6 runs =
  108 runs/side): 0 failures, exact established counts everywhere;
  N=100 walls Rouster 103/102/127 ms (c1/c2/c4) vs FRR 116/89/87;
  speaker CPU 0.12-0.29 vs 0.07-0.08 s — same shape as the VM grid
  (FRR ahead on wall at N=100, CPU gap ~2×).** · **E7 long-lived
  memory (rouster ×3, the novel-attribute shape: 10 rounds × 10k
  per-round-unique communities + 2 full withdraw/reannounce cycles =
  300k novel tuples): speaker RSS plateau 45.2 → 56.5 MB stable
  (56.2/56.8/56.9); the +11.3 MB increment = one 65,536-tuple sweep
  window at ~175 B/tuple (census) — the designed bound, quantitatively;
  core drains to ~baseline after full withdrawal + session loss;
  speaker post-withdrawal floor ~27 MB = allocator retention (table
  empty).** · **E4: Rouster 100k kernel-programming wall 1.18 s med
  (84.8k routes/s, core window CPU 1.345 s; dump-mode observer —
  Rouster finishes before observer dump pressure grows; 10k 0.108 s,
  1k 0.025 s). The same-run FRR comparator was NOT obtainable on this
  host: under every in-netns kernel observation (state dumps at 0.02/
  0.5 s + vtysh 5 s; an ip-monitor event counter) FRR's kernel-install
  stream stalls at a table fraction (85k / 10.8k) while its RIB
  completes (injector wire fully delivered; pfxRcd frozen with the
  stall); the event monitor ALSO stalls rousterd (22.2k) — withdrawn.
  E1-frr (no in-netns observer) shows no stall and a full kernel at
  capture; E1 oracles are RIB-basis on both sides. Prime suspect: the
  locked netlink buffer defaults (no sudo; the VM rig ran 32 MiB).
  Incumbent kernel-basis stays on the VM CPU-derived 116.5k routes/
  CPU-s with its standing caveat.** · harness deltas this session:
  bench-e4 BENCH_E4_MODE=frr + BENCH_E4_TIGHT_SECS + BENCH_E4_MONITOR,
  bench-observe --kernel-from-file, bench-flap --novel-rounds/
  --full-cycles, e2 BENCH_E2_NOVEL/BENCH_E2_FULL_CYCLES/
  BENCH_E2_INJ_IMAGE, e3 BENCH_E3_CPU{1,2,4}, all harnesses
  BENCH_BIN_DIR + probe-on-bench-net (the DGX lacks docker0; custom
  bridges work) · receipts: away/2026-10-19/bench/{dgx-e2-e7,dgx-e4}/
  (PROTOCOL.md + summaries + diagnostic observe.csvs); raw on
  dgx-spark-1:~/rouster-bench/target/bench-logs/. No verdict prose.

- 2026-10-19 · X-cells (bench-x.sh: e1diff/e4conv/e5recover/e6mixed/
  e7overload) · host=dgx-spark-1 (rig as the 2026-10-19 bare-metal E1
  entry) · **e1diff (100k slice): installed (prefix,nexthop) sets
  FRR 99,997 vs Rouster 99,998; ZERO FRR-only; ONE Rouster-only = the
  announced default 0/0 (Rouster installs, incumbent does not) —
  99,997 pairs identical.** · **e4conv (10k, eth0 down 4 s): both
  systems' installed count → 0 during the outage; NEITHER restores
  within 120 s of link-up (no session event; kernel-side link-down
  deletion invisible to desired-vs-believed reconcile on both sides —
  shared restoration gap, symmetric).** · **e5recover (100k):
  Rouster speaker crash = kernel routes persist (99,998 through the
  kill window), 5.7 s total recovery; Rouster core crash = forwarding
  intact, 8.8 s total. FRR speaker crash = immediate cleanup (kernel
  0), 40.6 s total with config re-push + replay; FRR zebra crash =
  stale-persist (99,997), recovery NOT completed in the 300 s window
  (bgpd zserv reconnect sends nothing — pinned-doc finding 5;
  harness-limited, no system claim).** · **e6mixed (rousterd + FRR
  mgmtd+staticd + rouster bgpd, 100k): static adds exact (3/3), BGP
  installed stable at 99,998 through static churn; static withdrawal
  unconfirmed in the 30 s window (disclosed).** · **e7overload (30
  rounds x 50%): storm ~60 s; drain to stable full 2.3 s both sides;
  timelines sustain 99,997-8; core RSS 8.1 MB post-storm.** ·
  receipts away/2026-10-19/bench/dgx-x-cells/; raw on the box under
  target/bench-logs/x-*. No verdict prose.

- 2026-10-19/20 · X round-2 cells (bench-seq.py + bench-x e1seq/
  e5cycles/e7overload-sweep/e45igp) · host=dgx-spark-1 (rig as the
  2026-10-19 bare-metal E1 entry) · **e1seq (10k, both systems,
  kernel-dump oracles): SEQ-1 interleave — Rouster installed set
  EXACTLY the computed 8,000-prefix expected set; FRR 7,999 with the
  one residual = the known default-route delta. SEQ-2 replacement —
  Rouster 10,000/10,000, ZERO duplicate prefixes; FRR 9,999, zero
  dups. SEQ-3 session-reset+re-add — Rouster 10,000/10,000 exact,
  zero dups (re-announce over the persisted table REPLACES); FRR
  9,999, zero dups.** · **e5cycles (mid-replay kill + reconnect ×3,
  both systems): 6/6 cells recover to the exact full count with zero
  duplicates.** · **e7 sweep (10% and 25% subsets, 10 rounds):
  sustained 99,997-8 through/after; drain 2.3 s both systems both
  shapes (subset-insensitive at these sizes).** · e45igp (IGP-under-
  BGP + mixed): CLOSED attempted-with-finding — topology proven by
  two manual replications (OSPF p2p adjacency FULL ~20 s both shapes;
  native side installs the OSPF-learned /32 into the core), automated
  cell fails at the peer's config delivery (daemons alive, config
  never applied; earlier "passes" were comparison-error artifacts,
  now guarded); E4/E6 IGP cells stay placeholders · receipts:
  away/2026-10-19/bench/dgx-x2/; raw on the box. No verdict prose.

- 2026-10-20 · X round-3 cells (e45igp native measured + probe;
  e5backend; e7 queue occupancy) · host=dgx-spark-1 (rig as the
  2026-10-19 bare-metal E1 entry; rousterd from tree d68efbe with the
  install-window occupancy instrumentation) · **e45igp native (rouster
  bgpd + rouster-ospfd; OSPF peer = FRR): adjacency Full; 10,000 BGP
  routes installed through an OSPF-only nexthop; peer-ospfd kill →
  withdrawn 9.7 s (63.2 s first run) → restart → restored 19.8 s
  (27.2 s first run); forwarding probe: ONE 19.0 s loss window
  (icmp_seq 43→139), no flap outside it.** Mixed/frr variants:
  harness config-commit loss inside the cell (diag captured; z5 smokes
  prove the attachments elsewhere) — recorded as finding, not claimed ·
  **e5backend (SIGSTOP at 30% installed, 10 s): 3/3, 88 overrun/silent
  events during the stall, recovery to exact 99,998 in 1.2-1.3 s
  after CONT. First version stalled a finished daemon (fixed-sleep
  bug, disclosed); receipts from the fixed cell.** · **e7 queues: peak
  in-flight 512 (= the F8 bound, saturated under overload), quiescent
  0 at 1 Hz sampling** · receipts away/2026-10-19/bench/dgx-x3/. No
  verdict prose.

- 2026-10-21 · X round-4: the mixed-IGP cell MEASURED (e45igp all three
  modes) · host=dgx-spark-1 (rig as the 2026-10-19 bare-metal E1 entry;
  rousterd tree ab533d5) · two real fixes on the way, both found by
  this cell: (harness) per-daemon `-f` config files replace the
  mgmtd-backed vtysh -b push (the async commit was lost in-cell; a
  printf quoting bug also wrote the file empty once) + FRR bgpd over
  an OSPF-learned nexthop needs `ebgp-multihop 2` (the single-hop
  connected-nexthop check rejects non-on-link next hops locally,
  without consulting the core); (SUT defect, fixed ab533d5, gate
  1860/0) NHT re-evaluation now rides the reconcile tick — bgpd's
  10.99.0.1 registration raced the native OSPF route's arrival and
  route events never re-armed NHT (link/address only), leaving
  "#paths 10000 unresolved" forever; zebra re-evaluates NHT on route
  changes; pinned by
  tick_nht_flips_a_registration_after_the_covering_route_arrives ·
  **measured (10k routes, OSPF-only nexthop, peer-ospfd kill+restore):
  native 10,000 baseline / 9.7 s withdraw / 19.9 s restore / probe one
  19.2 s loss window; mixed (FRR bgpd + native ospfd) 10,000 / 9.7 /
  19.9 / one 16.8 s window; frr (FRR bgpd + FRR ospfd, same core)
  10,000 / 9.7 / 10.5 / one 9.2 s window — withdrawal is
  dead-interval-driven (identical 9.7 s all modes); the restore gap is
  the OSPF speaker (FRR ospfd re-converges faster than the native
  ospfd on restart — a native-speaker follow-up, not a core
  difference)** · pre-fix failing runs kept with the diagnostics ·
  receipts away/2026-10-19/bench/dgx-x4/. No verdict prose.

- 2026-10-21 · X round-5 (e1rand generated campaign; e4partial
  attempt; e6 staticd withdrawal; e7 queues 200 ms; ospfd restore
  analysis) · host=dgx-spark-1 · **e1rand: 5 seed-driven random
  schedules per system over {A, W<n>, R<n>}, computed oracles —
  FRR 5/5 exact, Rouster 5/5 exact, zero duplicates both (0/0
  excluded as the e1diff-known delta). Two harness bugs found and
  fixed en route (index- vs lexicographic-sort; locale collation
  hiding exact agreement), disclosed in the receipt.** · e4partial
  closed attempted-with-finding: three-router shared-segment OSPF
  stalls one adjacency in LSDB exchange (Loading, 180 s) with BOTH
  the native and FRR speakers as SUT (not a Rouster defect); the
  two-segment rebuild did not form adjacency in-window; the
  per-nexthop isolation measurement stays a placeholder · **e6: FRR
  staticd withdrawal does not propagate via ANY harness surface
  (mgmtd push, SIGHUP, vtysh -c — live-probed; staticd EXIT leaves
  routes per the disclosed no-owner-cleanup design); adds remain
  deterministic 3/3; rouster's own staticd (z4) implements SIGHUP-diff
  withdrawal** · **e7 queues at 200 ms (own tick, gate 1860/0 + the
  known vty flake disclosed): peak 512 (F8 bound saturated), current
  0 in all 31 intra-storm samples — bursts drain in under 200 ms** ·
  ospfd restore decomposition (dgx-x4 logs): native 19.9 s = 9 s
  adjacency re-form + constant ~5 s Full→/32 (present on first
  bring-up too — LSA/SPF pacing, not restart damage) · receipts
  away/2026-10-19/bench/dgx-x5/. No verdict prose.

- 2026-10-21 · Rust-alternative baselines (reviews/
  rust-alternatives-plan.md, owner-ratified; RustyBGP speaker-level
  S-R + Holo end-to-end E-R; M-R rides the same runs) ·
  host=dgx-spark-1 (rig as the 2026-10-19 bare-metal E1 entries:
  SUT .20 cpus 5-9 single L3 cluster, injector .10 cpus 0-3, holo's
  kernel observer a third container sharing the SUT netns on
  10-14, rmem kernel-default, 0 overruns every rouster leg) ·
  versions: RustyBGP osrg/rustybgp @3dbf3e1 (2026-10-19 master,
  ACTIVELY maintained — the plan's unmaintained-vintage anticipation
  inverted; glibc + default tikv-jemallocator, lto workspace
  profile); Holo v0.9.0 (947daeb, 2026-02-21, latest release) with
  holo-cli pinned 6cffb9c (the contemporaneous CLI; master-era CLI
  speaks a newer gRPC API); gobgp v4.10.0 as the read-only oracle
  client (RustyBGP implements the GoBGP v4 API); all built rustc
  1.99.1 in rust:1-slim (trixie; 1.85 refused: tonic 0.14.6 needs
  1.88, uuid 1.28 needs 1.89); binary sha256s in versions.txt ·
  runtime image bench-alt-run:trixie (debian:trixie-slim +
  iproute2; the Rust systems link glibc — image base differs from
  frr-testbed:10.2.2, disclosed per §F same-host/engine rule) ·
  injector: OUT-OF-TREE mrt-replay variant + the RFC 4760
  multiprotocol IPv4-unicast capability in the OPEN (6 bytes;
  UPDATE stream unchanged; RustyBGP negotiates families ONLY from
  the MP-capability intersection and NOTIFICATION-3/1's IPv4 NLRI
  without it — reproduced); the SAME variant binary ran ALL FOUR
  legs; FRR/Rouster re-run with it reproduce the 2026-10-19 matrix
  (wall 30.657 vs 30.556, 12.663 vs 13.522; CPU/mem within 2%) ·
  feed: the pinned dump, full 1,126,490 · runs: 6 per leg (1 warmup
  + 5 measured) · oracles: RustyBGP = gobgp global-rib Destination
  count at 1 Hz (speaker-level ONLY — the default config programs
  no kernel FIB; verified every run; the kernel integration EXISTS
  at this rev as an opt-in [zebra.config] block, probe-confirmed to
  install proto bgp/186 at 2k); Holo = kernel proto-186 count from
  the paced observer (Holo installs BGP routes with the SAME
  rtnetlink tag as rousterd, holo-routing netlink.rs:225; dump cost
  1.65-1.75 s at full table recorded per row — completion carries
  up to one dump of quantization); FRR/Rouster = their established
  §R oracles · **S-R speaker ingest (first-UPDATE→speaker RIB
  full): FRR bgpd 30.657 s [p95 30.67] / RustyBGP 1.643 [3.36,
  min 0.66 — 1 Hz poll vs sub-second fill] / Rouster bgpd 4.888
  [4.95] (own-log EOR); speaker CPU 13.61 / 2.73 / 9.52 s; speaker
  B/pfx 919.3 / 1,026.0 (jemalloc default) / 452.8; RustyBGP RIB =
  1,126,481 = feed−9 (same accept count as Rouster)** · **E-R
  end-to-end (first-UPDATE→kernel complete): FRR (A) 30.657 [30.67]
  / Holo 32.666 [36.38] / Rouster (D) 12.663 [13.67]; SUT CPU
  25.27 (pair) / 47.65 (single process) / 27.01 (pair); suite B/pfx
  1,452.3 / 4,846.0 / 682.2; accepted kernel counts 1,126,484 /
  1,126,282 (= feed−208: Holo RFC 7606 treat-as-withdraw on AS_PATH
  parse strictness, deterministic every run, 0 injector
  NOTIFICATIONs) / 1,126,481** · Holo v0.9.0 robustness findings
  (disclosed): a northbound gRPC session racing bulk ingest panics
  the daemon (iana-bgp-community-types:no-export identity
  unresolvable in generated YANG serialization; reproduced 3/3 with
  1 Hz holo-cli polling, clean 4/4 without — the harness makes NO
  mid-run CLI calls); `show bgp summary` fails post-settle at 100k+
  (state fetch Cancelled); all measured cells 0 panics · both
  directions published: RustyBGP leads the speaker wall 3x over
  Rouster's EOR at 2.3x less speaker CPU while carrying 2.27x the
  speaker memory and no kernel table by default; Holo trails the
  incumbent wall by 6.5% (within oracle quantization) at 1.9x pair
  CPU and 3.34x pair memory; the native configuration leads every
  end-to-end metric · raw: dgx-spark-1 target/bench-logs/
  {rustybgp,holo,frr,rouster}-20261021T*; receipts
  away/2026-10-21/bench/rust-baselines/ (PROTOCOL.md + summaries +
  fold + median-run polls + versions + injector diff). No verdict
  prose.

- 2026-10-28 · X full-table e1diff (bench-x.sh e1diff, the 100k
  slice lifted to the full feed; cell unchanged except the limit)
  · host=dgx-spark-1 (rig as the 2026-10-19 X-cells entry; both
  legs sequential on bench-net, SUT .20 cpus 5-9, injector .10
  cpus 0-3) · versions: FRR 10.2.2 (frr-testbed:10.2.2), Rouster
  1.1.0 prebuilts ~/rouster-bench/bin (rousterd cd588377…, bgpd
  b06eb5cc…), injector the OUT-OF-TREE mrt-replay variant
  440f9f7f… for ALL legs via BENCH_BIN_DIR (stock bin/mrt-replay
  786935be… not used); LC_ALL=C on all sort/comm (host locale
  en_US.utf8) · feed: the pinned dump, full 1,126,490 (sha256
  61f0d40d…; REPLAY-PARSED routes=1126490 both legs, 556,132 msgs,
  EOR after the full request) · 2k smoke first (A=1,999 D=2,000,
  onlyA=0, onlyD=1) · **full run: installed (prefix,nexthop)
  kernel sets FRR 1,126,480 vs Rouster 1,126,481; ZERO FRR-only;
  ONE Rouster-only = the announced default 0/0 via 172.31.255.10
  (Rouster installs, incumbent does not) — 1,126,480 pairs
  identical; Rouster = feed−9, matching the 2026-10-21
  rust-baselines accept/kernel counts with the same injector;
  cell wall 80 s** · receipts away/2026-10-27/e1diff-full/
  (counts, NOTES.md with versions + injector sha256, replay logs,
  dump head/tails, full onlyA/onlyD); raw on the box
  target/bench-logs/x-e1diff-20261028T{102456Z,102545Z}. No verdict
  prose.

- 2026-10-30 · churn24 COMPLETION (owner decision D4,
  plans/decisions-2026-10-30.md; closes the START entry's "final
  samples land in a later entry") · the rouster-side 24 h × 100k
  flap-churn soak self-terminated at 21:55:31 CST 2026-10-30 (24 h
  28 m wall — the peer-bounce windows stretch the nominal schedule),
  96/96 blocks, 1{,}440 data rows (96 × 15, contiguous, 15 rows per
  block) · schedule census: 72 flap blocks + 12 flap+peer blocks
  (blocks 4/12/20/28/36/44/52/60/68/76/84/92, every 8) + 12 nexthop
  blocks · block wall: median 905 s [904-907]; the 12 peer-adjacent
  block deltas 996-997 s · row-level: 12 gaps of 152-153 s, exactly
  one per peer bounce (the finalizer's morning count of 5 was the
  first 5 of 12, seen through block ~40); each bounce shows kern
  99{,}998 → 153 s silence → withdrawal floor (0 at 6 of 12 bounces,
  7{,}692-25{,}000 mid-reinstall at the other 6) → recovery to
  99{,}998 within the block, all 12 recovered · memory PLATEAU, no
  drift: window-median rss over every 16-block window holds
  speaker 47.3-49.9 MB and core 25.0-25.1 MB across the full 24 h;
  final row rss_spk 47{,}612 kB / rss_core 25{,}132 kB; HWM constant
  from early run at 62{,}408 / 26{,}188 kB (the START entry's block-3
  snapshot values, rss_core 7-10 MB, predate the plateau) · discrep =
  2 on every settled row (desired 100{,}000 vs kernel feed−2 =
  99{,}998, the sweeps' convention; mid-withdrawal samples reach
  95{,}455) · final-kernel.txt = 99{,}998; both containers torn down
  cleanly by the driver · raw: rig
  `target/bench-logs/churn24-rouster-20261029T132813Z/` (samples.csv,
  schedule.txt, 96 block censuses, full daemon logs, final-kernel)
  mirrored verbatim to `away/2026-10-29/night2/A-CHURN-FINAL/`
  (1.7 GB) · bounded-behavior statement scope: this campaign, per the
  revision plan's P1 item; no broader claim. No verdict prose.

- 2026-10-31 · G1 FRR verification cells (owner decision D3's
  follow-up; the adjudication named two required cells before any
  FRR number from the c/n arms is cited) · c8-frr and n16-frr
  rerun once each on the same rig and harness shape (WL_RUNS=1,
  WL_SMOKE=0, BENCH_SUT_RMEM=0, bin-wl, SUT 5-9, inj 0-3; the
  variant script keeps the two cells only, mirrored at
  scripts/bench-wl-verify.sh via /tmp — identical to
  bench-wl-sweep.sh except CELLS and the RUNS default) · both
  cells reproduce the grid values deterministically: c8-frr
  kernel_last 99{,}135 (grid: 99{,}135 on all 6), n16-frr
  kernel_last 4 (grid: 4 on all 6) · the adjudication's "suspected
  observer failure" reading for the n-arm is REJECTED: the value
  is real FRR behavior at default configuration — zebra spends
  0.01 CPU-s (near-total install refusal) while bgpd's pfxRcd
  holds 99{,}998, consistent with the zebra-side nexthop
  resolution rejection the mixed-cell finding documented (the
  single-hop check rejects non-on-link nexthops) · c8's shortfall
  (863 prefixes) is equally deterministic, unattributed here ·
  paper impact: the workload-sensitivity text's
  default-config-rejection framing stands; FRR numbers from the
  c/n/stress arms stay labeled with the shortfall · raw: box
  target/bench-logs/verify-d3{,b}-20261031T0019{32,47}Z + logs/
  verify-d3{,b}.txt (first attempt hit the box's rmem sysctl
  denial; BENCH_SUT_RMEM=0 per the A-SWEEP disclosure). No verdict
  prose.

- 2026-10-31 · fail7 five-scenario injection campaign (ToN revision
  phase 5; owner decision D1 routed the cell here after the night
  lane's deleted driver; driver restored verbatim from 938d7dd at
  6b71a65, two latent harness bugs fixed and disclosed en route:
  the S3 readout polled for the full count where W2 ends at half
  the table (b6d065f; the first attempt's S3-frr "nones" row is
  superseded, raw kept), and S6 referenced the env name
  BENCH_NET_SUBNET where the script defines NET_SUBNET (204107b;
  set -u killed attempt 1 at S6-frr, its 3 rows kept)) · rig
  dgx-spark-1, lane-A shape (BENCH_BIN_DIR=bin-wl, SUT cpus 5-9,
  injector 0-3, announce-100k LIMIT=100000; DEVIATION from the
  6-run protocol disclosed: recovery-correctness cells with a
  boolean outcome and one t_consistent readout, not performance
  medians — single run per cell) · t_consistent = seconds from
  injection end to the kernel count reaching the scenario's
  expected level (poll 2 s, bound expected−40; intervention and
  probe anomaly recorded per cell):
  | scenario | frr 10.2.2 | rouster |
  |---|---|---|
  | S1 disconnect mid-replace | 2.5 s | 2.5 s |
  | S3 lost ack mid-withdrawal | 12.2 s | 12.3 s |
  | S4 late ack after retry | 12.3 s | 12.3 s |
  | S6 nexthop change mid-reconcile | 10.3 s | 10.3 s |
  | S7 five freeze/thaw cycles | 37.8 s | 37.7 s |
  S2 (restart during replay) and S5 (buffer overrun mid-install)
  reuse the standing e5cycles and e5backend receipts per the
  pre-registered design (e5cycles: 6/6 exact both systems; e5backend
  1.2-1.3 s is rouster-side, the incumbent cell not covered by that
  receipt) · every run cell: intervention=none, probe_anomaly=0;
  t_consistent is injection-dominated (each includes its frozen or
  blackholed window; the recovery tail is 2.3-2.7 s on both
  systems) · raw: box logs/f7-run.txt (attempt 1) + f7-run2.txt
  (attempt 2) + target/bench-logs/x-fail7-*/. No verdict prose.

- 2026-10-30 · G1 A-SWEEP adjudication (owner decision D3,
  plans/decisions-2026-10-30.md) · the 2026-10-29 A-SWEEP entry's
  pre-registered bar ("every run kernel = 99,998; wire-shape stats;
  6 runs/cell") is adjudicated against the Rouster side, which the
  sweep characterizes: all 18 rouster cells = 99,998 in every run,
  stats and runs present — G1 PASS on that criterion. The recorded
  FRR-side kernel_last deviations are classified, not adjudicated as
  failures: a-series 100,001 = FRR's own extra kernel routes (counting
  convention, expected); c-series 95,966-99,135 = pending
  verification (candidate-multiplicity behavior vs observation lag
  unresolved); n-series/stress "4" = suspected observer failure. Two
  FRR verification cells (one c-series, one n/stress arm) are REQUIRED
  before any FRR number from the c/n/stress arms is cited in the
  paper; a-series values may be cited with the +3 convention named.
  No verdict prose beyond this adjudication.

- 2026-10-28 · splitpin-e1 (the ISSUES.md item-5 decomposition,
  owner-deferred; away/2026-10-27 Q2) · rig = the receipted
  2026-10-21 shared cell unchanged (SUT .20 cpuset 5-9, injector
  .10 cpus 0-3, rmem kernel-default, same prebuilts, the 440f9f7f…
  injector variant) — NOT rerun for baselines — with the two SUT
  daemons re-pinned INSIDE the SUT cpuset after start and before
  inject: bgpd→5-7, rousterd→8-9, via the new BENCH_SPLIT_PIN knob
  (purely additive, unset = no-op; the Alpine frr image has no
  taskset applet and host-side taskset is EPERM unprivileged, so the
  host taskset runs through a throwaway --pid=host
  SYS_CHROOT+SYS_NICE chroot helper; every run log carries taskset
  -cp + in-container Cpus_allowed_list for both daemons, all
  threads) · shape: clean 100k smoke (6/6 checks), then 6 full-feed
  runs (1 warmup + 5 measured) · run-2 WEDGED at main 909,155:
  injector completed, bgpd received all 556,132 msgs + EOR (own EOR
  wall 4.992 s) then the bgpd→zapi stream stalled post-EOR while
  rousterd idled with ZERO rcvbuf-overrun warnings — NOT the
  2026-10-16 ENOBUFS signature; the poller stall guard never armed
  (its 64 KiB log-tail EOR oracle misses the EOR line buried ~474k
  zedge lines deep), wedge declared manually at +25 min frozen, ONE
  retry per the frozen bar (passed, kernel feed−9) substituting
  run-2 in the fold · **readouts vs the receipted shared cell:
  EOR_split 4.842 [p95 4.946, min 4.831, max 4.902] vs EOR_shared
  4.888 [4.95, 4.828, 4.928] — contention share 0.94% with per-run
  spread −0.3%..+1.2% (ranges overlap); bgpd CPU 9.305 vs 9.52;
  rousterd CPU 15.72 vs 17.49; wall_split 13.144 [13.642] vs 12.663
  [13.668] (the same bimodal 12.65/13.64 structure in both cells);
  kernel 1,126,481 = feed−9 in every completed run; 0 overruns; 0
  malformed** · both directions: disjoint halves leave the EOR
  window within run-to-run noise of the shared cell while rousterd
  CPU drops 10% (bgpd 2%), and one run of six wedged with a
  no-ENOBUFS post-EOR zapi-stall signature not seen in any shared
  5-9 cell · raw on the box target/bench-logs/
  rouster-20261028T{103932Z,104116Z(+fold),110925Z}; receipts
  away/2026-10-27/splitpin-e1/ (fold + raw + retry summaries, pin
  logs, WEDGE-EVIDENCE, PROTOCOL, harness diff). No verdict prose.

- 2026-10-28 · E2 gap sweep — the deferred pace dimension (the
  2026-10-16 addendum's deferred rate sweep; "cycles/s" mapped onto
  bench-flap.py `--round-gap`, the inter-burst pacing: per round =
  withdraw burst → gap → reannounce burst → gap; effective pace =
  10,000 / round period) · host=dgx-spark-1 LANE B (bench-net2
  172.31.254.0/24, SUT .20 cpus 12-16, injector .10 cpus 17, observer
  (SUT-netns, 0.05 s kernel loop) 18-19; lane A ran concurrently;
  rmem kernel default) · versions: FRR 10.2.2; Rouster prebuilts
  ~/rouster-bench/bin (rousterd cd588377… = ab533d5+ — NOT the
  2026-10-19 E2 baseline's 5fa1856, disclosed; bgpd b06eb5cc…);
  harness byte-identical to tree (BENCH_E2_ROUND_GAP already
  existed; no change) · feed: the pinned announce-100k.announce
  (sha256 6c9f4f7d…, 100k routes) EXCEPT its 100,000 NEXT_HOPs
  hard-code the LANE A injector 172.31.255.10 — on lane B nothing
  installs (isolated: FRR pfxRcd=10000 with zebra/kernel at 0;
  Rouster table full, kernel 0) — derived
  announce-100k-laneb.announce (sha256 47b79fa7…; the same
  NEXT_HOP-to-injector surgery mrt-replay applies in-flight;
  identical derived bytes on both SUTs per §F); injector base
  bench-flap-runner:local via the existing BENCH_E2_INJ_IMAGE knob
  (committed default bench-exabgp:local absent, registry
  unreachable) · shape: gaps {2.0, 0.5, 0.1} × {rouster, frr} × 6
  (1 warmup + 5 measured) = 36 runs, 100k slice, every-10th subset
  (10k), 10 rounds, storm otherwise the receipted shape; 10k-gap-0.5
  smoke both sides first (10/10 rounds, exact 9,000 kernel troughs,
  0 malformed) · **per-round reconvergence (kernel basis, med [p95],
  n=50): gap 2.0 — Rouster 0.331 [0.433] vs FRR 0.243 [0.317] (FRR
  ahead 1.36×; the receipted gap-2.0 baseline on the 5-9 placement +
  rousterd 5fa1856 was 0.285 [0.387] vs 0.130 [0.206], FRR 2.19× —
  placement+binary deltas disclosed, direction unchanged, magnitude
  narrower on lane B); gap 0.5 — Rouster 0.328 [0.431] vs FRR 0.244
  [0.334] (1.34×) — pace-INDEPENDENT from ~2.46k to ~9.35k cycles/s
  (<2% movement both systems); gap 0.1 (~37k cycles/s) — BOTH
  saturate: Rouster 1.365 [2.910] vs FRR 1.465 [2.689] (Rouster
  edges 1.07×; 4-6× inflation), round periods 0.27 s < restore
  times** · exact withdraw troughs (kernel, expected 89,998): gap
  2.0 50/50 + 50/50; gap 0.5 49/50 + 50/50; gap 0.1 Rouster
  sampling-limited 11/34 in-window samples (exact value seen, min
  89,998) while FRR NEVER dips to the trough mid-storm (min 92,843 —
  its kernel install/removal stream falls behind the 0.27 s rounds);
  post-storm plateaus exact every run (Rouster 99,998, FRR 99,997) ·
  session survival: 0 NOTIFICATION / 0 aborts / 6/6 FLAP-LINGER-END
  per cell; malformed 0, rejected 0 on all 36 · storm CPU med:
  speaker Rouster 1.42/1.24/1.17 s vs FRR 2.10/1.71/1.06 s (gap
  2.0/0.5/0.1); core Rouster 4.04/3.58/3.05 vs FRR 3.07/2.02/1.10 —
  the receipted shape (Rouster speaker-cheaper, core-costlier)
  persists at every gap · kernel-basis round walls R/F: 2.399/2.312 s
  (gap 2.0), 0.898/0.813 (0.5), 1.540/1.635 (0.1) · injector
  exonerated at the boundary: pacing exact (101 ms inter-burst med,
  requested 100), bursts 7-10 ms/61-73 ms, injector CPU 0.63-0.77 s
  per run (~15% of its 1-CPU duty at gap 0.1) — degradation is
  SUT-side on both systems · verdicts: GRID-PASS not met (gap-0.1
  exact-trough criterion), GRID-PARTIAL fired — boundary recorded
  between ~9.35k and ~37k cycles/s; stage-2 gap 0.05 NOT run (gate
  requires GRID-PASS) · receipts away/2026-10-27/e2-sweep/
  (PROTOCOL.md + REPORT.md + fold-grid.json + per-cell summaries,
  all-run metrics/poll/observe/flap + median-run gz SUT logs +
  driver/fold copies; bundle sha256 3dc0b636…); raw on the box
  target/bench-logs/e2-20261028T{103855Z,104726Z,105643Z,110210Z,
  110823Z,111302Z} + smoke {103546Z,103640Z}. No verdict prose.

- 2026-10-28 · X e4partial MEASURED (the per-nexthop isolation cell,
  a placeholder since round 3) · host=dgx-spark-1 LANE B (segment 1
  = bench-net2 172.31.254.0/24, segment 2 = bench-net3
  172.31.253.0/24 created for this cell; SUT .20 cpus 12-16, both
  peers + injector .10 cpus 17; lane A untouched) · the round-5
  two-segment failure re-diagnosed in the tree before any rerun:
  7ef9798's peer-ospfd config kept only the lo `network
  10.99.x.0/24 area 0` and dropped the transit one (peers ran OSPF
  on lo alone, no hellos on eth0, empty neighbor tables — a harness
  config bug, not a rig/protocol stall), and the same cell's
  `case FullFull` adjacency gate can never match p2p's `Full/-`
  (e45igp's `Full*` glob is correct); both fixed in the rebuilt cell,
  staged bring-up first: segment 1 alone Full in 6-13 s, both Full
  2 s after the segment-2 add · shape: SUT (rousterd cd588377… =
  ab533d5+ + native bgpd/ospfd prebuilts) with two p2p OSPF segments
  to two FRR-ospfd peers (lo dummies 10.99.0.1 / 10.99.1.1),
  injector announces 10k routes odd/even across the two recursive
  nexthops; the kernel carries the RESOLVED programming form (rib.rs
  gateway rewrite), so the per-set discriminator is the segment
  gateway (via 172.31.254.30 vs via 172.31.253.31); iproute2 on this
  image names 188=ospf (187 is isis) — OSPF filters use the name ·
  **native (rouster-ospfd): 2/2 runs ISOLATION-PASS — baseline
  10,000 (5,000/5,000); kill peer-1 ospfd → the segment-1 set
  5,000→0 in 18.1/11.8 s while the segment-2 set held 5,000/5,000
  (100.00%) and the total pinned at 5,000 through the trough, 0
  duplicate (prefix,via) pairs at every dump; restart peer-1 ospfd →
  exact prior counts (set-1 pre-vs-post dump diff 0 lines) in
  16.5/15.5 s; forwarding probes: dead-nexthop stream ONE 19.2/19.0 s
  loss window, healthy stream ZERO loss** · stage 2 (FRR ospfd as the
  SUT OSPF speaker): **2/2 ISOLATION-PASS — withdraw 9.6/11.7 s,
  persist 5,000/5,000, restore exact 16.6/16.5 s, probes one
  19.0/19.8 s dead-nexthop window only — the isolation is core
  behavior, speaker-independent** (disclosed: frrspf's
  post-adjacency ospf-routes.txt capture raced FRR's SPF throttle —
  empty at +8 s, both /32s present by BGP-resolution time, which the
  5,000/5,000 baseline requires) · frozen readouts pre-registered in
  the away program (BRINGUP-FAIL / ISOLATION-PASS / ISOLATION-PARTIAL):
  ISOLATION-PASS fired on both stages; withdraw is dead-interval
  paced, restore ~16-17 s under both speakers · receipts
  away/2026-10-27/ospf-dualseg/ (PLAN, TOPOLOGY, BRINGUP, configs,
  per-mode OBSERVATIONS + artifact bundles with the 1 Hz dualseg.csv,
  per-set kernel dumps, probes, flap logs); raw on the box
  target/bench-logs/x-e4partial-20261028T{114934Z,115131Z smoke,
  115958Z native, 120210Z frrspf}. No verdict prose.


- 2026-10-28 · speaker-opt (away/2026-10-27 Q6, the RustyBGP-gap
  ladder's first stream; decomposition → one default-off lever)
  · host=dgx-spark-1 LANE A (the receipted 2026-10-21 shared cell:
  bench-net, SUT .20 cpuset 5-9, injector .10 cpus 0-3,
  BENCH_SUT_RMEM=0; injector the 440f9f7f… variant; rousterd the
  cd588377… prebuilt throughout) · **Stage 1a limit sweep** (baseline
  bgpd b06eb5cc…, limits {100k, 300k, 600k, full} × 3 runs, 12/12
  clean, 0 malformed/overruns, kernel basis feed−2/−5/−5/−9 every
  run): EOR medians 0.356 / 1.209 / 2.495 / 4.879 s → 3.56 / 4.03 /
  4.16 / 4.33 µs per route (marginal 4.27 / 4.29 / 4.53 µs — mildly
  superlinear, intercept ≈ tens of ms); bgpd CPU 0.72 / 2.43 / 4.99 /
  9.59 s → 7.2 / 8.1 / 8.3 / 8.5 µs per route; CPU/EOR ≈ 1.97 at
  every size (≈half the speaker CPU rides the EOR-serial session
  task); RustyBGP comparator receipted at full only: EOR 1.643 s =
  1.46 µs/route, CPU 2.73 s = 2.42 µs/route · **Stage 1b
  decomposition**: (i) the established BGPD_EST_PROFILE instrument on
  one full-feed run (EOR 4.911): decode_ms=1244 + update_ms=1564 +
  eor_ms=16 of the 4,911 ms window — 2,087 ms (42%) un-instrumented
  middle; (ii) log census from the receipted 2026-10-28 splitpin raw:
  sut-bgpd.log = 294,768,971 B = 556,132 `UPDATE received` +
  1,126,490 `route add -> zebra` + 1 EOR line, ANSI escapes into a
  file; (iii) feed-packing replication of the injector surgery+pack
  (cross-validated: 16,623 distinct tuples at 100k vs the M3 census's
  16,621): msgs 46,424@100k / 556,132@full, distinct tuples 16,623 /
  152,024 → the pre-registered S1 ONE-ENTRY attr memo hits only
  123/46,424 = 0.3% and 902/556,132 = 0.2% — **S1 as pre-registered
  ranked OUT by measurement** (tuples recur — 73% of UPDATEs repeat
  an earlier tuple — but not consecutively; a full-map variant stays
  a candidate); S2 election batching ranked out (sink share 1.56 s
  dominated by per-prefix work, batching saves only lock overhead)
  · **Stage 2 lever (LANDED)**: `BGPD_QUIET_INGEST=1` (default OFF,
  the BGPD_EST_PROFILE runtime-gate precedent) — the per-UPDATE
  `UPDATE received` line sampled to one per 65,536 messages (message
  0 always: the harness first-UPDATE/EOR oracle basis stays
  line-precise; the F5 preview is built only on lines that log), the
  per-route `route add/delete -> zebra` lines shed, ANSI off; pinned
  unit tests quiet_ingest_env_parsing /
  quiet_ingest_samples_update_lines_at_64k /
  update_preview_bounded_four_entries_f5_shape; tree ee3c2b1+,
  bgpd c4012062… (~/rouster-bench/bin-q6; baselines untouched);
  harness: the additive BENCH_SUT_ENV knob (bench-e1-ingest.sh +
  bench-x.sh, unset = no-op) · **gate**: fmt + clippy -D clean;
  workspace 1,863/0 (receipted 1,860 + the 3 new; no vty flake,
  first-run pass); 100k e1diff-style installed-set equality ON vs
  OFF, same binary: 99,998 = 99,998, onlyOFF 0 / onlyON 0 (each leg
  vs FRR also onlyD=1 = the known announced-default 0/0 delta,
  identical both legs); full feed × 6 runs ON: **EOR median 3.639 s
  [3.695 p95, min 3.609] vs the receipted 4.888 [4.95] = −25.5%;
  bgpd CPU median 6.58 s vs 9.52 = −30.9%; kernel 1,126,481 =
  feed−9 every run; 0 malformed; the ON-run bgpd log 1,817 B (9
  UPDATE lines) vs 294,768,971 B; update_msgs reads 9 under quiet —
  the true 556,132 is the injector's own REPLAY count per run
  (disclosed oracle-basis note)**; OFF control (same binary, env
  unset, 3 runs full): EOR 4.918 [4.834..4.989], CPU 9.67 — within
  the receipted cell's spread, so the delta attributes to the flag,
  not the binary; rousterd CPU unchanged (17.3-17.5 both legs) ·
  both directions: the flag cuts the speaker EOR window 26% and
  speaker CPU 31% on this rig/shape by shedding 1.68 M log events
  per full feed — observability cost: the per-UPDATE/per-route INFO
  surfaces exist only at default OFF; the residual gap to RustyBGP
  after the lever: EOR 3.639 vs 1.643, CPU 6.58 vs 2.73 · Stage 3 (the ladder's next
  lever) reported separately if it runs · receipts away/2026-10-27/speaker-opt/
  (REPORT.md + artifacts: 4 sweep summaries, estprof leg + final
  snap, feed-packing script+outputs, e1diff ON/OFF kernel sets +
  notes, ON/OFF/control full-feed summaries, log census); raw on the
  box target/bench-logs/rouster-20261028T{123432Z,123631Z,123842Z,
  124111Z sweep; 125254Z estprof; 132055Z smoke; 132440Z gate-ON;
  133011Z control-OFF} + x-e1diff-20261028T{132149Z OFF,132253Z ON}.
  No verdict prose.

- 2026-10-28 · speaker-opt stage 3 — the ladder's second lever
  (BGPD_FAST_ELECTION, the Stage-1 table's next rank after
  BGPD_QUIET_INGEST landed) · same rig/binaries discipline (bgpd
  8219cab7… = stage-2 tree + the lever, ~/rouster-bench/bin-q6b;
  rousterd cd588377…; injector 440f9f7f…) · mechanism: the
  single-candidate fast path in LocRib::recompute_prefix — with
  exactly one candidate the §9.1 ladder returns it by construction,
  so the generic arm's score/alive vectors and unconditional winner
  clone are skipped, and an identical re-announcement compares
  (Arc pointer-shortcut Route::eq) before any clone; default OFF,
  equivalence pinned by single_candidate_fast_path_agrees_with_bulk_
  recompute (the F1 incremental-vs-bulk shape extended with the
  unchanged-destination arm) · **gate**: workspace 1,864/0 (stage-2's
  1,863 + the equivalence test); 100k e1diff installed sets: OFF vs
  BGPD_FAST_ELECTION=1 and OFF vs both-flags — 99,998 = 99,998 with
  0/0 deltas both comparisons (each leg's onlyD=1 = the known
  announced-default 0/0, unchanged) · **readouts**: full feed × 6
  runs with the flag ALONE: EOR median 4.489 s [4.575, 4.429..4.575]
  vs the receipted 4.888 = −8.2%; bgpd CPU 8.86 vs 9.52 = −6.9%
  (vs the stage-2 same-binary OFF control 4.918/9.67: −8.7%/−8.4%)
  — **below the frozen 15% LANDED bar; tests green, deltas zero →
  the NO-GAIN disposition (the mimalloc precedent): committed behind
  the default-off flag with the honest share** · stacked with
  BGPD_QUIET_INGEST (both flags ON, 6 runs): EOR median 3.439 s
  [3.447, 3.414..3.461] / bgpd CPU 6.33 = vs the receipted baseline
  −29.6% EOR / −33.5% CPU; vs lever-1 alone (3.639/6.58) the
  increment is −5.5% EOR / −3.8% CPU; kernel 1,126,481 = feed−9
  every run of every leg; 0 malformed · both directions: the
  election fast path is worth single digits alone and stacks
  additively; the speaker-gap ladder's two landed flags together
  leave EOR 3.439 vs RustyBGP's receipted 1.643 and CPU 6.33 vs
  2.73 · receipts away/2026-10-27/speaker-opt/ (stage-3 e1diff
  kernel sets + the two full-feed folds); raw on the box
  target/bench-logs/rouster-20261028T{134440Z stacked, 134948Z
  fast-only} + x-e1diff-20261028T{134103Z OFF, 134207Z ON2,
  134311Z ON12}. No verdict prose.

- 2026-10-29 · e1rand2 conformance campaign, training half (night
  program lane B stage B-TRAINING: 20 random-schedule seeds × both
  systems, limit 10000, computed oracle; plus the smoke-gate
  repair story that preceded it) · host=dgx-spark-1 LANE B:
  bench-net2 172.31.254.0/24, SUT 172.31.254.20 cpuset 12-16,
  injector 172.31.254.10 cpu 17, alt_nh 172.31.254.11 (the N-op
  second injector address) — disjoint from lane A's in-flight
  b1-* cells on bench-net (bench-x startup cleanup matches only
  x2r-*/x7-* here) · versions: BENCH_BIN_DIR=~/rouster-bench/
  bin-wl — rousterd 09b183c8…, rousterctl 1872ef76…, bgpd
  c0edf7ea…, mrt-replay 04c4ef48… (bin-wl/SHA256SUMS mirrored);
  feed rib.20261015.0400.mrt sha256 61f0d40d…70f; announce
  announce-100k-laneb.announce sha256 47b79fa7… (training + retry;
  the failed-smoke input announce-100k.announce is 6c9f4f7d…);
  harness scripts/bench-x.sh e1rand2 carrying the pre-registered
  Stage-0 BENCH_X_SEEDS knob (box backup .bench-x.sh.pre-seedsknob;
  identical Mac-side edit landed bench-scope this fold); staged
  runner laneB-night.sh (batch invocations of 5 K-indices; fail7
  mutual-exclusion gates vs lane A) · **training verdicts: frr
  20/20 X-PASS, 0 X-FAIL; rouster 20/20 X-PASS, 0 X-FAIL; diff=0
  and dups=0 on all 40 verdicts; expected final pairs 4523-10000
  (median 8126), schedule length 13-61 ops (median 27), boundaries
  2-4 per schedule; dwindow rows present on every verdict — 56 D
  + 28 Rs rows total, per-side row-count distribution identical
  (4×1-row, 10×2-row, 6×3-row)**; per-seed (exp=pairs+1 both
  sides; dw f= / r= frr/rouster dwindow rows; batch dirs
  104107Z/105358Z/110936Z/112532Z = seeds 2-6/7-11/12-16/17-21):
  s2 exp 10000 ops34/b2 dw f[Rs 0 D 0] r[Rs 10000 D 10000] ·
  s3 exp 10000 ops13/b4 dw f[D 9999] r[D 10000] · s4 exp 7449
  ops37/b3 dw f[Rs 0 D 0 D 0] r[Rs 10000 D 7320 D 7856] · s5 exp
  6264 ops24/b3 dw f[Rs 0 D 0] r[Rs 10000 D 6946] · s6 exp 8401
  ops20/b4 dw f[D 0 D 0] r[D 10000 D 10000] · s7 exp 8527 ops31/b2
  dw f[D 0 D 0] r[D 9091 D 8202] · s8 exp 8857 ops25/b3 dw f[D
  9999 D 0] r[D 10000 D 10000] · s9 exp 7857 ops30/b4 dw f[D 9999
  Rs 0] r[D 10000 Rs 10000] · s10 exp 8395 ops20/b2 dw f[D 8262]
  r[D 8263] · s11 exp 7661 ops61/b4 dw f[D 0 D 0 Rs 9999] r[D
  7351 D 7076 Rs 10000] · s12 exp 9177 ops51/b3 dw f[Rs 0 D 0
  Rs 0] r[Rs 10000 D 9364 Rs 10000] · s13 exp 7030 ops24/b3 dw
  f[D 0 D 0] r[D 8750 D 7536] · s14 exp 10000 ops26/b4 dw f[Rs
  9999 Rs 0] r[Rs 10000 Rs 10000] · s15 exp 10000 ops27/b2 dw
  f[D 0 D 0] r[D 9384 D 9423] · s16 exp 4523 ops46/b3 dw f[D 0
  Rs 0 D 0] r[D 10000 Rs 10000 D 4523] · s17 exp 4854 ops17/b3
  dw f[D 0] r[D 6000] · s18 exp 10000 ops27/b2 dw f[Rs 0 D 0]
  r[Rs 10000 D 9584] · s19 exp 7715 ops22/b2 dw f[D 0] r[D
  10000] · s20 exp 6130 ops48/b4 dw f[D 0 D 0 Rs 0] r[D 8500 D
  8417 Rs 10000] · s21 exp 6999 ops46/b3 dw f[Rs 0 D 0 Rs 0]
  r[Rs 10000 D 8944 Rs 10000] · **smoke-gate story (seed 51,
  limit 2000, base=0): two pre-repair attempts FAILED both sides
  with identical numbers — kept verbatim, not rerun (094748Z,
  095846Z): "X-FAIL e1rand2 frr seed=51: pairs=0 expected=999
  diff=999 dups=0" / "X-FAIL e1rand2 rouster seed=51: pairs=0
  expected=999 diff=999 dups=0", dwindow=[Rs 239 Rs 0] both sides
  both attempts — classified BLOCKED-class evidence (harness-input
  fault, below); the orchestrator-authorized retry #3 (103410Z)
  passed both sides: frr pairs=999/999 diff=0 dups=0 dw=[Rs 1999
  Rs 0], rouster pairs=999/999 diff=0 dups=0 dw=[Rs 2000 Rs
  2000]** · deviation disclosures: (a) SEED NUMBERING — the runner
  does not set BENCH_X_SEED and bench-x.sh:867,995 defaults
  SEED=1 with SD=K+1 in the loop (bench-x.sh:1018), so the
  BENCH_X_SEEDS K-lists {1-5, 6-10, 11-15, 16-20} (training) and
  {21-25} (held-out) actually ran seeds 2-21 and 22-26 — not
  1-20 and 21-25 as intended; the 20-training + 5-held-out counts
  and the train/held-out disjointness are intact (uniform +1
  shift); owner decision on a seed-1 top-up pending; the held-out
  invocation x-e1rand2-20261029T114014Z folds under stage
  B-HELDOUT, not here · (b) REPAIR — the two failed smoke
  attempts used announce-100k.announce, whose next-hops are baked
  for lane A's subnet (all head-2000 entries 172.31.255.10, the
  bench-net injector address): non-connected on bench-net2, NHT
  never resolves, no A/R-op route enters the kernel FIB; observed
  239 = |N16∪N24∪N12| − |R23∩N| = 250 − 11, window2 = 0 (W2
  withdraws every even ordinal and every N-flip index is even),
  final 0/999 — full derivation away/2026-10-29/night2/
  laneB-diagnosis.md; the repair was the orchestrator-authorized
  retry #3 with the pre-staged announce-100k-laneb.announce
  (2026-10-28 18:34, prefix corpus identical, only the next-hop
  field differs: all 172.31.254.10); the staged runner
  laneB-night.sh received exactly 2 edits (ANN swap to the
  lane-correct file; fail7 mutual-exclusion gate inserted at the
  training-loop body top and again before the held-out
  invocation), diff-proven against .laneB-night.sh.pre-repair in
  away/2026-10-29/night2/laneB-relaunch.md · (c) LANE B env —
  bench-net2 172.31.254.0/24, SUT cpus 12-16, injector cpu 17,
  feed sha256 61f0d40d…70f, binaries per the mirrored bin-wl
  SHA256SUMS · raw: box dgx-spark-1:~/rouster-bench/target/
  bench-logs/x-e1rand2-20261029T{104107Z, 105358Z, 110936Z,
  112532Z training batches 1-4; 094748Z, 095846Z failed
  pre-repair smokes verbatim; 103410Z authorized passing retry}
  + runner log nightB-20261029T104107Z.log; Mac mirror away/
  2026-10-29/night2/B-TRAINING/ (all seven invocation dirs +
  bin-wl/SHA256SUMS). No verdict prose.

- 2026-10-29 · e1rand2 conformance campaign, held-out half (night
  program lane B stage B-HELDOUT: the 5 held-out random-schedule
  seeds × both systems, limit 10000, computed oracle, single
  invocation dir) · host=dgx-spark-1 LANE B, same rig discipline
  as the training-half entry above (2026-10-29): bench-net2
  172.31.254.0/24, SUT 172.31.254.20 cpuset 12-16, injector
  172.31.254.10 cpu 17, alt_nh 172.31.254.11; BENCH_BIN_DIR=
  ~/rouster-bench/bin-wl — rousterd 09b183c8…, rousterctl
  1872ef76…, bgpd c0edf7ea…, mrt-replay 04c4ef48… (SHA256SUMS
  mirrored away/2026-10-29/night2/B-TRAINING/bin-wl/); feed
  rib.20261015.0400.mrt sha256 61f0d40d…70f; announce
  announce-100k-laneb.announce 47b79fa7… — both runner inputs
  identical to every training batch (laneB-night.sh lines 6-7,
  19-20); harness scripts/bench-x.sh e1rand2 with the
  BENCH_X_SEEDS knob · **held-out verdicts: frr 5/5 X-PASS,
  0 X-FAIL; rouster 5/5 X-PASS, 0 X-FAIL; diff=0 and dups=0 on
  all 10 verdicts; expected final pairs 7610-10000 (median 9100),
  schedule length 17-49 ops (median 20), boundaries 2-3 per
  schedule (median 2); dwindow rows present on every verdict,
  per-side row-count distribution identical (2×1-row + 1×2-row +
  2×3-row = 10 rows; 6 Rs + 4 D each side); the executed op
  schedule is identical between sides on every seed (mirrored
  rand2-<seed>-{frr,rouster}-exec.txt ops strings)**; per-seed
  (exp=pairs+1 both sides; dw f= / r= frr/rouster dwindow rows):
  s22 exp 9100 ops20/b2 dw f[Rs 0 D 0] r[Rs 10000 D 9487] ·
  s23 exp 8708 ops45/b3 dw f[Rs 0 Rs 0 Rs 0] r[Rs 10000 Rs 10000
  Rs 10000] · s24 exp 10000 ops49/b3 dw f[D 0 D 0 D 0] r[D 10000
  D 10000 D 10000] · s25 exp 10000 ops17/b2 dw f[Rs 9999] r[Rs
  10000] · s26 exp 7610 ops18/b2 dw f[Rs 0] r[Rs 10000] · with
  this stage the lane-B night campaign stands at 52 X-PASS /
  0 X-FAIL over post-repair runs (retry smoke 2 + training 40 +
  held-out 10; the two pre-repair failed smokes stay verbatim
  BLOCKED-class evidence per the training entry) · deviation
  disclosure — SEED NUMBERING: this batch ran seeds 22-26, not
  21-25 as intended: laneB-night.sh line 19 selects the held-out
  K-list via BENCH_X_SEEDS="21 22 23 24 25" but sets neither
  BENCH_X_SEED nor E1RAND2_HELDOUT (the notes header records
  base=1 heldout=0), and bench-x.sh:867,995 defaults SEED=1 with
  SD=K+1 in the K-loop, so K 21-25 → seeds 22-26; the held-out
  set {22..26} is disjoint from the training set {2..21} (uniform
  +1 shift; 5+20 counts intact; seed-1 top-up decision pending) —
  full numbering derivation, smoke-gate repair, and lane-B
  environment disclosures: training-half entry above, not
  repeated here; the fail7 mutual-exclusion gate preceding this
  invocation (laneB-night.sh:18) never engaged (A-SWEEP-DONE
  absent throughout — correct); no FAIL/BLOCKED seeds in this
  stage · raw: box dgx-spark-1:~/rouster-bench/target/bench-logs/
  x-e1rand2-20261029T114014Z (71 files) + runner log
  nightB-20261029T104107Z.log (held-out section: cell start
  line 173 → done line 215); Mac mirror away/2026-10-29/night2/
  B-HELDOUT/x-e1rand2-20261029T114014Z/ (71 files, 7.4 MB,
  nothing >200 MB, no gzip). No verdict prose.

- 2026-10-29 · P0 workload-diversity grid: attribute-uniqueness /
  ADD-PATH / nexthop-pool sweeps + pairwise stress cell + ablation
  arms (night program lane A, fold unit A-SWEEP: fixed 100k scale,
  6 runs per cell = 1 warmup + 5 measured, both systems per sweep
  and stress cell, ablation arms rouster-only per the pre-registered
  cell table; baseline cells NOT rerun — the natural-feed 100k
  receipts stand per the do-not-rerun rule) · host=dgx-spark-1
  LANE A: bench-net 172.31.255.0/24, SUT cpus 5-9, injector cpus
  0-3 (BENCH_SUT_CPUS=5-9 BENCH_INJ_CPUS=0-3; harness defaults
  differ, disclosed below) · versions: BENCH_BIN_DIR=~/rouster-bench/
  bin-wl — rousterd 09b183c8…, rousterctl 1872ef76…, bgpd c0edf7ea…,
  mrt-replay 04c4ef48… (bin-wl/SHA256SUMS mirrored away/2026-10-29/
  night2/B-TRAINING/bin-wl/; sha-identical to lane B's independently
  built set); feed rib.20261015.0400.mrt sha256 61f0d40d…70f; grid
  dir wl1-20261029T101418Z (30 cells, 2,419 files, 6.0 GB); harness
  scripts/bench-wl-sweep.sh @ 732752d + lane A's line-82 set -u fix
  (split local; committed bench-scope this fold, 5fbf7ee) driving
  scripts/bench-e1-ingest.sh · wire-shape stats lines present in
  every cell both systems (REPLAY-ATTR-STATS + REPLAY-NH-STATS, one
  pair per cell, identical between systems within each cell):
  a-series distinct_tuples 39158/60058/79072/100000 routes=100000
  addpath=1 nh=1; c-series tu 33246/66492/132984 ap 2/4/8 nh=1;
  n-series tu 44898/77020/98355/99999 ap=1 nh 16/256/4096/65535;
  stress tu=800000 ap=8 nh=65535; ablation arms tu=16623 ap=1
  nh=1 · **per-cell medians [p95] over the 5 measured runs
  (kernel_last = main_prefixes_last per the grid fold; EOR =
  wall_bgp_level_s, emitted on rouster runs only; spk/core =
  bgpd/zebra field names (rousterd-bgpd / rousterd-core daemons on
  the rouster side); B/pfx = (RSS_final−RSS_empty)×1024/100000,
  ledger convention for the median, p95 from per-run deltas;
  overruns = Σ over measured runs; medians cross-checked
  cell-for-cell against the grid's own fold.json — 30/30 match):**

  | cell | wall_external_s | EOR_s | spk CPU_s | core CPU_s | spk B/pfx | core B/pfx | kernel_last | overruns_Σ |
  |---|---|---|---|---|---|---|---|---|
  | a25-frr | 30.781 [30.791] | — | 1.02 [1.03] | 0.99 [1.00] | 1533.9 [1534.6] | 554.2 [568.5] | 100001 | 0* |
  | a25-rouster | 2.773 [2.789] | 0.448 [0.468] | 0.82 [0.86] | 1.55 [1.56] | 642.2 [649.2] | 233.9 [236.0] | 99998 | 0 |
  | a50-frr | 30.761 [30.765] | — | 1.23 [1.23] | 1.01 [1.04] | 2035.3 [2037.9] | 557.6 [564.0] | 100001 | 0* |
  | a50-rouster | 2.753 [2.769] | 0.560 [0.565] | 0.94 [0.99] | 1.56 [1.59] | 824.5 [828.0] | 232.8 [234.4] | 99998 | 0 |
  | a75-frr | 30.758 [30.763] | — | 1.43 [1.44] | 1.05 [1.07] | 2540.6 [2541.5] | 558.7 [564.0] | 100001 | 0* |
  | a75-rouster | 2.740 [2.754] | 0.603 [0.651] | 0.98 [1.10] | 1.54 [1.57] | 969.3 [983.0] | 232.4 [233.4] | 99998 | 0 |
  | a100-frr | 30.739 [30.746] | — | 1.64 [1.67] | 1.05 [1.07] | 3040.9 [3044.2] | 557.5 [569.4] | 100001 | 0* |
  | a100-rouster | 2.731 [2.741] | 0.691 [0.748] | 1.08 [1.19] | 1.56 [1.57] | 1132.7 [1142.0] | 234.5 [235.8] | 99998 | 0 |
  | c2-frr | 0.667 [0.677] | — | 1.80 [1.91] | 0.84 [0.87] | 1358.1 [1358.7] | 540.9 [541.2] | 95966 | 0* |
  | c2-rouster | 2.677 [2.684] | 1.278 [1.297] | 1.71 [1.95] | 1.54 [1.57] | 764.0 [764.7] | 233.1 [233.8] | 99998 | 0 |
  | c4-frr | 0.352 [0.374] | — | 3.34 [3.35] | 0.86 [0.89] | 2007.3 [2008.1] | 545.4 [547.6] | 98103 | 0* |
  | c4-rouster | 3.359 [3.366] | 2.377 [2.392] | 2.82 [2.85] | 1.53 [1.56] | 1364.3 [1366.5] | 234.5 [234.7] | 99998 | 0 |
  | c8-frr | 1.252 [1.275] | — | 6.31 [6.36] | 0.91 [0.94] | 3495.6 [3499.6] | 546.2 [548.5] | 99135 | 0* |
  | c8-rouster | 6.275 [6.291] | 4.667 [4.809] | 5.13 [5.27] | 1.55 [1.56] | 2588.0 [2590.6] | 233.9 [235.7] | 99998 | 0 |
  | n16-frr | 30.787 [30.793] | — | 0.79 [0.81] | 0.01 [0.02] | 892.8 [895.6] | 1.4 [1.6] | 4 | 0* |
  | n16-rouster | 30.790 [98.308] | 0.633 [0.642] | 1.01 [1.03] | 34.16 [101.71] | 705.9 [706.9] | 235.9 [236.7] | 99998 | 0 |
  | n256-frr | 30.775 [30.798] | — | 0.82 [0.82] | 0.01 [0.03] | 1020.2 [1022.6] | 2.6 [5.7] | 4 | 0* |
  | n256-rouster | 30.784 [193.139] | 0.667 [0.675] | 1.05 [1.11] | 34.25 [196.61] | 949.1 [955.5] | 235.0 [239.0] | 99998 | 0 |
  | n4096-frr | 30.775 [30.785] | — | 1.04 [1.06] | 0.06 [0.08] | 1109.7 [1111.8] | 32.2 [32.9] | 4 | 0* |
  | n4096-rouster | 30.761 [32.473] | 0.660 [0.663] | 1.04 [1.06] | 34.18 [35.85] | 1110.1 [1112.8] | 246.9 [247.7] | 99998 | 0 |
  | n65535-frr | 30.766 [30.781] | — | 36.20 [36.29] | 6.36 [6.57] | 1274.3 [1275.8] | 476.2 [476.5] | 4 | 0* |
  | n65535-rouster | 30.778 [33.469] | 0.664 [0.672] | 1.04 [1.07] | 34.19 [36.87] | 1120.5 [1121.8] | 425.5 [428.0] | 99998 | 0 |
  | stress-frr | 1.746 [1.753] | — | 7.52 [7.56] | 2.33 [2.43] | 2220.1 [2224.6] | 416.8 [504.1] | 4 | 0* |
  | stress-rouster | 28.757 [115.497] | 5.272 [5.308] | 5.75 [5.77] | 31.76 [118.40] | 7978.6 [7979.9] | 424.5 [424.9] | 99998 | 0 |
  | ab-ctl-rouster | 2.784 [2.801] | 0.355 [0.364] | 0.72 [0.72] | 1.57 [1.57] | 475.7 [478.3] | 234.4 [235.9] | 99998 | 0 |
  | ab-intern-rouster | 2.781 [2.805] | 0.345 [0.350] | 0.71 [0.74] | 1.57 [1.59] | 699.2 [702.8] | 234.7 [236.4] | 99998 | 0 |
  | ab-win64-rouster | 2.782 [2.799] | 0.353 [0.431] | 0.70 [0.95] | 1.72 [1.75] | 474.8 [494.6] | 230.1 [231.5] | 99998 | 0 |
  | ab-win8-rouster | 2.786 [2.799] | 0.352 [0.357] | 0.70 [0.71] | 1.77 [1.77] | 475.0 [476.0] | 230.9 [231.0] | 99998 | 0 |
  | ab-win1-rouster | 3.785 [3.798] | 0.343 [0.350] | 0.68 [0.69] | 2.60 [2.64] | 477.3 [480.8] | 230.5 [230.9] | 99998 | 0 |
  | ab-fast1-rouster | 2.784 [2.800] | 0.335 [0.341] | 0.68 [0.70] | 1.56 [1.57] | 473.7 [477.7] | 234.7 [236.6] | 99998 | 0 |

  (*) overruns_Σ on the frr side: the harness collects
  netlink_rcvbuf_overruns / malformed / rejected on rouster runs
  only — frr per_run records carry none of these fields, so the 0*
  entries mean "field not collected", not "measured 0"; the
  rouster side records malformed=0 and rejected=0 on every run of
  all 18 rouster cells. kernel_count_last is null on both systems
  throughout this grid (poller's sut_kernel_count column empty);
  the frr per_run additionally records pfxrcd_last, verbatim:
  a-series and n-series 99998 on all runs of all cells; c2
  191925/191925/191925/191923/191925/191923; c4 392397/392397/
  392398/392397/392397/392396; c8 793051/793051/793050/793050/
  793050/793050; stress 239600/238320/237830/237990/237810/238660
  (rouster runs carry pfxrcd_last=null — field presence differs by
  system, disclosed) · ablation pairs (G2: same binary
  rousterd 09b183c8… on every arm, levers are env vars only;
  deltas vs the in-grid reference arm ab-ctl, median − median,
  numbers only): interning ab-intern (ROUSTER_ATTR_INTERN=0) vs
  ab-ctl (=1): spk B/pfx +223.5, core B/pfx +0.3, wall −0.003,
  EOR −0.010, spk CPU −0.01, core CPU +0.00; ROUSTER_NL_WINDOW=64:
  wall −0.002, EOR −0.002, spk CPU −0.02, core CPU +0.15, spk
  B/pfx −0.9, core B/pfx −4.3; NL_WINDOW=8: wall +0.002, EOR
  −0.003, spk CPU −0.02, core CPU +0.20, spk B/pfx −0.7, core
  B/pfx −3.5; NL_WINDOW=1 (serial): wall +1.001, EOR −0.012, spk
  CPU −0.04, core CPU +1.03, spk B/pfx +1.6, core B/pfx −3.9;
  BGPD_FAST_ELECTION=1: wall +0.000, EOR −0.020, spk CPU −0.04,
  core CPU −0.01, spk B/pfx −2.0, core B/pfx +0.3 · spread facts
  from the wide-p95 cells (numbers only): rouster n-series/stress
  wall_external_s per-run values sit on a coarse ladder in this
  grid (observed per-cell min→max incl. warmup: n16 19.78→80.81,
  n256 30.78→137.82, n4096 18.76→33.77, n65535 17.78→57.78,
  stress 16.77→79.78); the frr cells' wall_external_s per-run
  spreads are ≤0.04 s in every cell (largest: n16-frr 0.031 s) ·
  **kernel_last verbatim, every cell (the G1 bar reads "every run
  kernel = 99,998"; deviations listed without adjudication — the
  stress shape samples mid-flap by design; whether any deviation
  satisfies the bar is the owner's call, not the fold's; nothing
  rerun, no bars adjusted): all 18 rouster cells = 99,998 on all
  6 runs each (warmup included); frr cells: a25/a50/a75/a100-frr
  = 100001 on all 6 runs each; c2-frr = 95966, 95966, 95966,
  95965, 95966, 95965; c4-frr = 98103, 98103, 98103, 98103,
  98103, 98102; c8-frr = 99135 on all 6; n16/n256/n4096/n65535-frr
  = 4 on all 6 runs each; stress-frr = 4 on all 6 runs** ·
  deviation disclosures (all evidenced in away/2026-10-29/night2/
  laneA-launch.md): (a) BENCH_SUT_RMEM=0 on the smoke and every
  chain run — this box's kernel 6.11.0-1014-nvidia does not
  namespace net.core.rmem_*, so the rcvbuf-sysctl leg of the
  2026-10-16 harness fix has never been active on this box;
  identical to every prior box receipt (comparability preserved) ·
  (b) box source tree was 10 tracked files stale vs Mac 732752d
  (crates/bgpd, crates/netlink-dp, crates/rousterd); exactly those
  10 files were synced before the build, rest untouched · (c)
  build host = Mac (box has no Rust toolchain): the four
  aarch64-unknown-linux-musl binaries were cross-built on the Mac
  from the exact 732752d tree and shipped to bin-wl/ + SHA256SUMS;
  SHAs matched lane B's independent build of the same tree · (d)
  lane A placement env BENCH_SUT_CPUS=5-9 / BENCH_INJ_CPUS=0-3 per
  the receipted lane placement (harness default SUT cpus 4-11
  differs) · (e) Stage-0 smoke (2k, combined shape) passed
  2000/2000 on the SECOND attempt: attempt 1 failed at container
  start (runc "permission denied" on net.core.rmem_default — the
  (a) root cause), relaunch with BENCH_SUT_RMEM=0 passed;
  separately, the 2k rehearsal grid (smoke-a-20261029T094515Z)
  passed smoke+a25+a50+a75 and was wedged at a100 by lane B's
  concurrent feed-layout normalization (~09:44Z rename raced the
  in-flight docker cp) — cross-lane event, wedged grid killed and
  replaced by the canonical-path chain; full story + the lane B
  side in laneB-diagnosis.md and STATE.jsonl (18:12/18:24 entries) ·
  (f) containers are named b1-sut/b1-inj-<ts>-<run> by the harness
  (the lane prompt guessed wl1-*; wl1- is the grid-dir prefix) ·
  (g) harness patch: lane A's uncommitted bench-wl-sweep.sh
  line-82 set -u fix (one `local` with two assignments split into
  two `local`s — no semantic change, only occurrence of the
  pattern in the seven drivers) committed bench-scope this fold as
  its own commit (5fbf7ee) · raw: box dgx-spark-1:~/rouster-bench/
  target/bench-logs/wl1-20261029T101418Z/ (30 cell dirs +
  fold.json, 2,419 files, 6.0 GB, largest single file 194 MB —
  nothing >200 MB, mirrored uncompressed) + runner log
  ~/rouster-bench/nightA-20261029T101418Z.log (sweep section: first
  cell line 2 → "bench-wl-sweep: done" line 1108); Mac mirror
  away/2026-10-29/night2/A-SWEEP/wl1-20261029T101418Z/ (2,419
  files verified by count + sha256 spot-checks vs box). No verdict
  prose.

- 2026-10-29 · churn24 24-hour flap-churn soak, rouster side —
  START receipt, run LIVE at fold time (night program lane A, fold
  unit A-CHURN-START; this is NOT a results entry — the run is
  DO-NOT-KILL and completes ~2026-10-30 21:28 CST; final samples
  and the completion fold land in a later entry after that time)
  · started 2026-10-29 21:28:13 CST (13:28:13Z), detached PID
  1128867 (`bash scripts/bench-churn24.sh ~/rouster-bench/
  announce-100k.announce rouster`), host=dgx-spark-1 LANE A:
  bench-net 172.31.255.0/24, SUT cpus 5-9, injector cpus 0-3
  (same placement as the A-SWEEP chain) · parameters:
  side=rouster hours=24 limit=100000 (CHURN24_HOURS/BENCH_X_LIMIT
  defaults) = 96 blocks × 15 min, phase=flap throughout so far,
  per-block ops per schedule.txt cycling W3,R3 → W4,R4 → W5,R5 ·
  versions: BENCH_BIN_DIR=~/rouster-bench/bin-wl — rousterd
  09b183c8…, rousterctl 1872ef76…, bgpd c0edf7ea…, mrt-replay
  04c4ef48… by bin-wl/SHA256SUMS reference (mirrored
  away/2026-10-29/night2/B-TRAINING/bin-wl/; sha-identical set
  to A-SWEEP's); sole feed input announce-100k.announce
  (13,773,861 B) sha256 6c9f4f7d…7ced, mounted /feed.announce,
  injector driver scripts/bench-seq.py · harness
  scripts/bench-churn24.sh @ adb9fdeb · crash → fix → relaunch
  chain: first launch 21:05 CST died ~100 s in (quoting bug at
  bench-churn24.sh:80-83 — the first embedded double quote CLOSES
  the outer sh -c string, so /etc/rouster-bgp.conf was never
  written, rouster-bgpd exited, the first sampler pass died
  silently in rss() under set -e, and the EXIT trap removed both
  c24 containers); crash artifact churn24-rouster-20261029T130501Z
  preserved verbatim (header-only samples.csv 1 line, schedule
  "block 1/96 phase=flap ops=W3,R3" only, blocks/ empty) and
  mirrored this fold — nothing rerun; orchestrator-authorized fix
  commit adb9fdeb (quoting only, receipted pattern
  scripts/bench-x.sh:84-91; post-fix script sha256 473ed63c…b79a0,
  Mac == box byte-identical); relaunch 21:28:13 CST; stability
  gates +3 min and +6 min PASS (config 6/6 lines present in the
  SUT, rouster-bgpd running pid 35, samples.csv rows 3 then 5,
  no leaked printf lines in the new runner log); full story in
  away/2026-10-29/night2/laneA-recovery.md + laneA-churn24-fix.md
  + STATE.jsonl 21:26 / 21:27:37 / 21:34:31 entries · point-in-
  time snapshot facts (mirror taken 2026-10-29T14:10:34Z =
  22:10:34 CST, sha-verified against the box at transfer time;
  the box copy keeps growing after this): samples.csv 42 lines =
  header + 41 data rows (block 1: 15 rows, block 2: 15, block 3:
  11 with block 3 still open), timestamps 21:29:52 → 22:10:05 CST,
  sampling deltas contiguous 60–62 s (40 deltas: 28×60 s, 11×61 s,
  1×62 s; none >62 s); columns populated, constant within each
  block — kern 33333 / 25000 / 20000 (blocks 1/2/3), rss_spk
  34460 / 24800 / 24224 kB, rss_core 9996 / 8264 / 7284 kB,
  hwm_spk 54780 kB and hwm_core 25716 kB constant across all
  three blocks, discrep 66667 / 75000 / 80000; blocks/1-census.txt
  + 2-census.txt written (288 B each, bgpd route-add log tails);
  runner log 195 B at snapshot = header line + block 1/96 + 2/96
  + 3/96 start lines · raw: box dgx-spark-1:~/rouster-bench/
  target/bench-logs/churn24-rouster-20261029T132813Z/ (LIVE,
  growing) + crash artifact ~/rouster-bench/target/bench-logs/
  churn24-rouster-20261029T130501Z/ (static) + runner log
  ~/rouster-bench/nightA-recovery-churn24-20261029T132813Z.log
  (LIVE; 4-line snapshot copy alongside the Mac mirror); Mac
  mirror away/2026-10-29/night2/A-CHURN-START/live/
  churn24-rouster-20261029T132813Z/ (point-in-time, 6 files) +
  away/2026-10-29/night2/A-CHURN-START/crash-artifact/
  churn24-rouster-20261029T130501Z/ (4 entries incl. empty
  blocks/ dir). No verdict prose.
