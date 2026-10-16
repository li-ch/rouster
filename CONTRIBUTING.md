# Contributing to Rouster

Thanks for looking under the hood. This file is the short version of how
to land a change; the project's shape and rules live in
[AGENTS.md](AGENTS.md), [docs/architecture.md](docs/architecture.md) and
[docs/implementation-plan.md](docs/implementation-plan.md).

## Build & gate

Rust **stable** toolchain (no nightly features in the tree):

```sh
cargo build --release

# The gate — all three must pass before a commit:
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

If your shell doesn't source your profile (CI containers, scripts,
terminals launched oddly), cargo may not be on PATH — prefix commands with
`PATH=$HOME/.cargo/bin:$PATH`.

Protocol code carries two extra rules: **no `unsafe`** and **no new
dependencies** without an explicit note in the commit message saying why
the fence is being crossed (the workspace runs deliberately lean — see the
comments in `Cargo.toml`).

## Commits

Imperative mood with a scope prefix — look at `git log` for the pattern:

```
rib: add best-path selection
zapi: answer ospfd's NHT registration from the kernel mirror
docs: add CONTRIBUTING
```

Update documentation in the same change that alters behavior:
`docs/implementation-plan.md` Appendix C is **append-only** (status ticks
cite their evidence), and interop results always extend
`docs/interop/frr-10.2-interop.md` rather than rewriting it.

## Wire formats: pin, never guess

FRR's ZAPI drifts across versions and is not fully specified in prose, so
every wire fact in this repo is pinned empirically against FRR **10.2.2**
and recorded in
[docs/interop/zapi-10.2-pinned.md](docs/interop/zapi-10.2-pinned.md) —
that file is the codec's ground truth (see
[docs/README.md](docs/README.md) for how the pinning was done and the
rules). In practice:

- A new ZAPI message or body field is implemented only after it has been
  observed on the wire (capture tools: `zapi-sniff`,
  `zapi-notify-probe` in `crates/zapi`), with the fixture committed under
  `crates/zapi/tests/fixtures/` and the pinned doc extended in the same
  change.
- Numbers from other FRR versions, from the FRR dev guide, or from memory
  are **not** authority — observations against 10.2.2 are.
- Never paste FRR (or other GPL project) source into this repository;
  derive wire facts from captures and observed behavior instead.

Draft-dependent SAVNET wire protocols follow the same pattern behind the
`experimental-savnet` feature flag, with the implemented draft version
pinned in docs (implementation-plan §4).

## Smoke tests

Integration evidence is container-based and lives in `scripts/`:

- Every `scripts/test-*.sh` is auto-discovered by `scripts/run-smokes.sh`
  (glob filter: `scripts/run-smokes.sh 'z5*'`; logs land in
  `target/smoke-logs/`).
- Scripts are **self-cleaning**: whatever containers/netns/veth they
  create get torn down in traps, including on failure.
- Scripts **never pull images**. They build rousterd for musl on the host
  and copy the binary into containers from cached local images (base
  image override: `ROUSTER_TEST_BASE_IMAGE`). A new smoke script should
  state its image prerequisites in its header comment.
- A change that touches kernel-visible behavior ships with a smoke script
  that proves it (or extends an existing one), not just unit tests.

Anything that changes how a real FRR daemon behaves when attached belongs
in `docs/interop/frr-10.2-interop.md` too — future readers will want to
know what was observed, not just what was intended.

## Fuzzing the wire codecs

AGENTS.md invariant 7: every wire codec is fuzzed with cargo-fuzz. Each
codec crate carries a `fuzz/` subproject in cargo-fuzz's
independent-workspace layout — its own `Cargo.toml` (a path dependency
on the crate, `libfuzzer-sys`, and a `[workspace]` table of its own), so
the fuzz crates build outside the Rust workspace and the root manifest
never mentions them. Targets: `zapi_decode`, `bgp_decode`,
`ospf_packet_decode`, `isis_pdu_decode`, `bfd_packet_decode`,
`rtr_pdu_decode`. The oracle is the decode `Result` — `Ok` and `Err` are
both fine; a panic (unwrap, index, slice) inside the codec is the bug.

Nightly is required to *drive* the fuzzers (libFuzzer's sanitizers ride
`-Z` flags) — that's the nightly toolchain, not nightly *features*: the
workspace tree and the fuzz targets themselves stay stable-language.
`rustup toolchain install nightly` once, then from a codec crate:

```sh
cargo install cargo-fuzz                      # once per machine
cd crates/bgpd
cargo +nightly fuzz build --fuzz-dir fuzz bgp_decode
mkdir -p fuzz/corpus/bgp_decode
cp fuzz/seeds/*.bin fuzz/corpus/bgp_decode/   # the checked-in seeds
cargo +nightly fuzz run --fuzz-dir fuzz bgp_decode -- -max_total_time=90
```

`fuzz/corpus/` and `fuzz/artifacts/` are gitignored (cargo-fuzz's
template); `fuzz/seeds/` is checked in — real FRR 10.2.2 wire frames for
zapi, encode-API output for the other five. Extend it whenever a new
message shape lands that the decoders should survive.

A crash writes `fuzz/artifacts/<target>/crash-*` plus the panic and stack
to the run log. Reproduce and minimize:

```sh
cargo +nightly fuzz run  --fuzz-dir fuzz <target> <crash-file>
cargo +nightly fuzz tmin --fuzz-dir fuzz <target> <crash-file>
```

Fix the codec, then keep the crashing input (as `fuzz/crashes/` holds
the RTR ErrorReport catch) so the fix carries its regression file.

## CI: the three pipelines

- **`ci.yml` (push/PR)** — the fast gate: `cargo fmt --check`,
  `clippy -D warnings` (plus the musl leg that actually compiles the
  netlink dataplane), unit tests, and a `bash -n` syntax pass over
  the smoke scripts. It never starts a container.
- **`smokes.yml` (nightly ~03:00 UTC + manual dispatch)** — the full
  `scripts/run-smokes.sh` (34 scripts, ~20 min, 40-min budget). The
  job builds the testbed image from `docker/frr-testbed.Dockerfile`
  (the reversed recipe of the image the suite was developed against —
  provenance and pins in `docker/README.md`), pre-seeds every other
  image tag the scripts pin, pre-builds the musl binaries, and runs
  the runner unmodified. Smoke logs upload as an artifact on failure.
- **`fuzz.yml` (nightly ~04:30 UTC + manual dispatch)** — the codec
  fuzz net: a seeded 90-second libFuzzer burst per target on the
  nightly toolchain (see "Fuzzing the wire codecs" above). It never
  gates pushes; a red leg means a real finding — the crash file and
  run log upload as artifacts for local reproduction.

### Running the suite locally

`scripts/run-smokes.sh` assumes docker works and the image tags exist
(no pulls, ever): `frr-testbed:10.2.2`, `rouster-nft:local`,
`gortr:local`, and the two alpine bases. From a clean checkout:

```sh
docker build -t frr-testbed:ci -f docker/frr-testbed.Dockerfile docker/
docker tag frr-testbed:ci frr-testbed:10.2.2   # the tag the scripts pin
docker build -t rouster-nft:local -f docker/nft-base.Dockerfile docker/
scripts/run-smokes.sh          # or a subset: scripts/run-smokes.sh 'z5*'
```

Linux runners need the musl target (`rustup target add
x86_64-unknown-linux-musl`); each script builds the binaries it
needs. Logs land in `target/smoke-logs/`.
