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

| # | question | options | Your decision |
|---|---|---|---|
| D1 | injector for E1/E2 | (a) exabgp replaying generated announce files; (b) small in-repo Rust MRT→BGP replayer (new dev tool, more control, more work); (c) both — (a) to start, (b) if (a) bottlenecks the injector itself | ___ |
| D2 | criterion dev-dep for E7 | (a) yes, all crates that need it; (b) one crate first (zapi) | ___ |
| D3 | bench job in CI | (a) nightly manual-dispatch only; (b) every push, non-gating; (c) skip CI, local only | ___ |
| D4 | host | (a) Linux box if available (best); (b) Mac Docker Desktop with `host=darwin-vm` labeling and the 2× unresolved rule | ___ |
| D5 | comparison set | (a) FRR only (the oracle; images cached); (b) FRR + BIRD (needs a bird image added to the cached set) | ___ |
| D6 | first claim to publish | (a) E1+E5 together (headline + memory); (b) E7 first (cheapest, no public comparative claim); (c) all at once when §R complete | ___ |

## R. Results ledger (append-only)

- (empty — runs append here: `{date, experiment, host, versions
  {rouster, frr, bird, kernel}, feed checksum, runs, median, p95,
  raw-log path, notes}`)

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
