#!/usr/bin/env bash
# bench-alloc-ab.sh — the S15-b allocator A/B (docs/benchmarks.md §R,
# 2026-10-16): the E1 100k-slice protocol run twice on the same build
# tree — the default allocator (side A) and mimalloc behind the
# `alloc-mimalloc` cargo feature (side B) — receipt-gated adoption.
#
# Mechanism (disclosed): bgpd's Cargo.toml carries mimalloc as an
# OPTIONAL dep behind `alloc-mimalloc` (default OFF; repo commit in
# PROTOCOL.txt). A plain cargo dependency is linker-discarded without
# a src-side reference, so side B is built from a SNAPSHOT COPY of the
# tree plus the 3-line cfg-gated `#[global_allocator]` activation
# point in crates/bgpd/src/bin/bgpd.rs (the hook diff is recorded in
# PROTOCOL.txt; the repo's bgpd src is NOT modified by this stream —
# the hook lands via the orchestrator on adoption). Side A is the
# SAME snapshot, feature off — the hook is cfg-stripped, so A/B
# differ by exactly the allocator (+ the dep). Both sides build in
# rust:alpine (linux/aarch64, musl native): the rig's host musl
# cross-build has no C toolchain for libmimalloc-sys's cc build, so
# the container is the reproducible path; both sides use the same
# compiler, same flags, same tree.
#
# Receipts per side: MIMALLOC_VERBOSE=1 in the daemon env on every
# run (side B's bgpd log shows the mimalloc init banner; side A shows
# none — the negative control proving the env var is inert under the
# default allocator), plus nm/strings symbol checks on both binaries.
#
# Protocol (§F shape, identical to bench-e1-ingest.sh's rouster mode):
# same feed (pinned route-views MRT, --limit 100000), same injector
# (in-repo mrt-replay, unpaced, hold 90), same SUT shape (rousterd +
# bgpd on frr-testbed:10.2.2 with the P0-b rcvbuf sysctls), the
# bench-poll.py external observer, bench-summarize.py per side, then
# an A/B fold (medians + p95, per-run B/prefix). Placement is
# isolated from sibling streams: net bench-net-s15b 172.31.253.0/24,
# SUT cpus 12-16, injector cpu 17 (the P0-b concurrent-stream
# precedent). Runs: 1 warmup + 5 measured per side, alternating after
# the warmups.
#
# Usage:
#   scripts/bench-alloc-ab.sh <raw-mrt>
# Env: BENCH_AB_RUNS (default 6), BENCH_AB_BUILD_IMAGE (rust:alpine),
#   BENCH_NET_NAME/BENCH_NET_SUBNET/BENCH_SUT_IP/BENCH_INJ_IP/
#   BENCH_SUT_CPUS/BENCH_INJ_CPUS (placement), BENCH_AB_SKIP_BUILD=1 +
#   BENCH_AB_BIN_A/BENCH_AB_BIN_B/BENCH_AB_BIN_SHARED (reuse binaries),
#   BENCH_TIMEOUT (default 900).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

FEED_MRT=$(cd "$(dirname "${1:?usage: bench-alloc-ab.sh <raw-mrt>}")" && pwd)/$(basename "$1")
LIMIT=100000
RUNS=${BENCH_AB_RUNS:-6}

SUT_AS=65000
INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net-s15b}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.253.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.253.20}
INJ_IP=${BENCH_INJ_IP:-172.31.253.10}
SUT_CPUS=${BENCH_SUT_CPUS:-12-16}
INJ_CPUS=${BENCH_INJ_CPUS:-17}
IMAGE=frr-testbed:10.2.2
BUILD_IMAGE=${BENCH_AB_BUILD_IMAGE:-rust:alpine}
HOLD=90
TIMEOUT=${BENCH_TIMEOUT:-900}
SUT_RMEM=${BENCH_SUT_RMEM:-33554432}
SUT_SYSCTLS=""
if [ "$SUT_RMEM" != 0 ]; then
    SUT_SYSCTLS="--sysctl net.core.rmem_default=$SUT_RMEM --sysctl net.core.rmem_max=$((SUT_RMEM * 2))"
fi

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *)             echo "unknown arch $(uname -m)" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/alloc-ab-$TS"
OUT_ABS="$PWD/$OUT_DIR"   # absolute: docker -v needs host paths, not names
mkdir -p "$OUT_DIR"
echo "bench-alloc-ab: feed=$FEED_MRT limit=$LIMIT runs/side=$RUNS out=$OUT_DIR"
echo "  net=$NET_NAME/$NET_SUBNET sut=$SUT_IP cpus=$SUT_CPUS inj=$INJ_IP cpus=$INJ_CPUS"

# The 3-line activation point applied to the SNAPSHOT copy (never to
# the repo tree). Recorded verbatim in PROTOCOL.txt.
HOOK='// S15-b alloc-mimalloc activation point: when the feature is on,
// mimalloc becomes bgpd'"'"'s global allocator (the A/B measured in
// docs/benchmarks.md §R, 2026-10-16).
#[cfg(feature = "alloc-mimalloc")]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;
'
export HOOK

apply_hook() { # <tree>
    python3 - "$1" <<'PYEOF'
import os, sys
tree = sys.argv[1]
path = os.path.join(tree, "crates/bgpd/src/bin/bgpd.rs")
src = open(path).read()
anchor = "\nfn main() {"
assert src.count(anchor) == 1, "expected exactly one fn main()"
hook = os.environ["HOOK"]
open(path, "w").write(src.replace(anchor, "\n" + hook + anchor))
print(f"hook applied to {path}")
PYEOF
}

# =========================================================================
# Phase 1 — build (snapshot + container)
# =========================================================================
if [ "${BENCH_AB_SKIP_BUILD:-0}" = 1 ]; then
    echo "==> build skipped (BENCH_AB_SKIP_BUILD=1)"
    mkdir -p "$OUT_DIR/bin-A" "$OUT_DIR/bin-B" "$OUT_DIR/bin-shared"
    cp "${BENCH_AB_BIN_A:?}" "$OUT_DIR/bin-A/bgpd"
    cp "${BENCH_AB_BIN_B:?}" "$OUT_DIR/bin-B/bgpd"
    for b in rousterd rousterctl mrt-replay; do
        cp "${BENCH_AB_BIN_SHARED:?}/$b" "$OUT_DIR/bin-shared/$b"
    done
else
    echo "==> phase 1: snapshot + container build"
    SNAP="$OUT_ABS/tree"
    mkdir -p "$SNAP"
    git archive HEAD | tar -x -C "$SNAP"
    apply_hook "$SNAP"
    { diff -u <(git show HEAD:crates/bgpd/src/bin/bgpd.rs) \
              "$SNAP/crates/bgpd/src/bin/bgpd.rs" || true; } > "$OUT_DIR/hook.diff"

    # Named volume: crate cache across the (re)builds inside this A/B.
    docker volume inspect ab-cargo-cache >/dev/null 2>&1 || docker volume create ab-cargo-cache >/dev/null

    echo "    building in $BUILD_IMAGE (native musl, no --target: the"
    echo "      image's host triple IS $MUSL_TARGET; rust-lld needs the"
    echo "      native lib dirs on the search path for proc-macro links)"
    # rust:alpine + rustup: proc-macro host dylibs link with rust-lld,
    # which does not search /usr/lib or gcc's libgcc dir by default —
    # pass both. Computed, not pinned, so an image refresh keeps working.
    docker run --rm \
        -v "$SNAP":/w -v ab-cargo-cache:/cargo -w /w \
        -e CARGO_HOME=/cargo \
        "$BUILD_IMAGE" sh -c '
            set -e
            G=$(gcc -print-libgcc-file-name)
            export RUSTFLAGS="-C link-arg=-L/usr/lib -C link-arg=-L${G%/*}"
            rustc -V && cargo -V
            cargo build --release -p rousterd --bin rousterd 2>&1 | tail -1
            cargo build --release -p rousterctl --bin rousterctl 2>&1 | tail -1
            cargo build --release -p bgpd --bin mrt-replay 2>&1 | tail -1
            cargo build --release -p bgpd --bin bgpd 2>&1 | tail -1
            mkdir -p /w/.ab-out
            cp target/release/bgpd /w/.ab-out/bgpd-A
            cargo build --release -p bgpd --bin bgpd --features alloc-mimalloc 2>&1 | tail -1
        '
    # A/B live in the same target dir (feature toggle rebuilds bgpd):
    # A was copied before the feature build overwrote it. B is the
    # feature build's output; the shared tools are untouched by it.
    mkdir -p "$OUT_DIR/bin-A" "$OUT_DIR/bin-B" "$OUT_DIR/bin-shared"
    cp "$SNAP/.ab-out/bgpd-A" "$OUT_DIR/bin-A/bgpd"
    cp "$SNAP/target/release/bgpd" "$OUT_DIR/bin-B/bgpd"
    for b in rousterd rousterctl mrt-replay; do
        cp "$SNAP/target/release/$b" "$OUT_DIR/bin-shared/$b"
    done
    rm -rf "$SNAP/.ab-out"

    echo "==> phase 2: verification receipts (grep + banner)"
    VRF="$OUT_DIR/verify"
    mkdir -p "$VRF"
    # Byte-level checks on the host (mimalloc strings / symbol names are
    # ASCII in the ELF); alpine has no binutils, so no nm/strings there.
    for side in A B; do
        {
            echo "== side $side =="
            echo "mimalloc strings: $(grep -ac mimalloc "$OUT_DIR/bin-$side/bgpd" || true)"
            echo "mi_malloc symbol-name hits: $(grep -ac mi_malloc "$OUT_DIR/bin-$side/bgpd" || true)"
        } >> "$VRF/symbols.txt"
        # Functional check: --validate-config with MIMALLOC_VERBOSE=1 —
        # side B's binary must print the mimalloc init banner, side A
        # (default allocator) must not (the negative control).
        docker run --rm -v "$OUT_ABS":/o:ro --entrypoint sh alpine:3.20 -c "
            printf 'router bgp 65000\n neighbor 10.0.0.1 remote-as 65412\n' > /tmp/v.conf &&
            MIMALLOC_VERBOSE=1 /o/bin-$side/bgpd --validate-config /tmp/v.conf > /tmp/out.log 2>&1;
            echo \"exit=\$?\"; echo \"mimalloc banner lines: \$(grep -c mimalloc /tmp/out.log || true)\";
            head -3 /tmp/out.log
        " > "$VRF/banner-$side.txt" 2>&1
    done
    cat "$VRF/symbols.txt" "$VRF/banner-A.txt" "$VRF/banner-B.txt"
fi

if command -v sha256sum >/dev/null; then
    sha256sum "$OUT_DIR/bin-A/bgpd" "$OUT_DIR/bin-B/bgpd" \
        "$OUT_DIR/bin-shared/"* > "$OUT_DIR/binaries.sha256"
else
    shasum -a 256 "$OUT_DIR/bin-A/bgpd" "$OUT_DIR/bin-B/bgpd" \
        "$OUT_DIR/bin-shared/"* > "$OUT_DIR/binaries.sha256"
fi
FEED_SHA=$(shasum -a 256 "$FEED_MRT" | awk '{print $1}')
{
    echo "bench-alloc-ab.sh protocol record"
    echo "date_utc:        $(date -u +%Y%m%dT%H%M%SZ)"
    echo "repo_head:       $(git rev-parse HEAD)"
    echo "tree:            snapshot of HEAD + hook.diff (below)"
    echo "build:           $BUILD_IMAGE container, native musl ($MUSL_TARGET)"
    echo "build_rustc:     $(docker run --rm "$BUILD_IMAGE" rustc -V)"
    echo "feed:            $FEED_MRT"
    echo "feed_sha256:     $FEED_SHA"
    echo "limit:           $LIMIT"
    echo "rig:             net=$NET_NAME $NET_SUBNET sut=$SUT_IP cpus=$SUT_CPUS inj=$INJ_IP cpus=$INJ_CPUS"
    echo "hold:            $HOLD (unpaced)"
    echo "sut_rmem:        $SUT_RMEM"
    echo "kernel:          $(uname -r)"
    echo "--- binaries.sha256 ---"
    cat "$OUT_DIR/binaries.sha256"
    echo "--- hook.diff (snapshot-only; repo src untouched) ---"
    cat "$OUT_DIR/hook.diff" 2>/dev/null || echo "(skipped build: no hook.diff)"
} > "$OUT_DIR/PROTOCOL.txt"

# =========================================================================
# Phase 3 — the E1 100k protocol, per side (1 warmup + RUNS-1 measured,
# warmups first, then alternating)
# =========================================================================
perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=ab-s15b-) >/dev/null 2>&1 || true

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

start_sut() { # name bin-dir
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    for b in rousterd rousterctl; do
        docker cp "$OUT_DIR/bin-shared/$b" "$1:/usr/local/bin/$b"
    done
    docker cp "$2/bgpd" "$1:/usr/local/bin/rouster-bgpd"
    docker exec "$1" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /run/rouster/zserv.api' > /etc/rouster.conf"
    docker exec -d "$1" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
    wait_up "$1" "rousterd zapi listening" 30 "grep -q 'zapi: listening' /var/log/rousterd.log"
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /run/rouster/zserv.api' \
        'router bgp $SUT_AS' \
        ' bgp router-id $SUT_IP' \
        ' neighbor $INJ_IP remote-as $INJ_AS' \
        ' neighbor $INJ_IP passive' \
        ' hold-time $HOLD' \
        > /etc/rouster-bgp.conf"
    docker exec "$1" sh -c "rouster-bgpd --validate-config /etc/rouster-bgp.conf"
    # MIMALLOC_VERBOSE=1 on BOTH sides: side B logs the mimalloc init
    # banner (the active-allocator receipt); side A is the negative
    # control (the env var is inert without mimalloc).
    docker exec -d "$1" sh -c "export MIMALLOC_VERBOSE=1; rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
    wait_up "$1" "rouster bgpd listening" 15 "grep -q 'bgpd: listening' /var/log/rouster-bgpd.log"
}

start_injector() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" \
        -v "$FEED_MRT":/feed.mrt:ro \
        --entrypoint sleep alpine:3.20 infinity >/dev/null
    docker cp "$OUT_DIR/bin-shared/mrt-replay" "$1:/usr/local/bin/mrt-replay"
}

INJ_ARGS="--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
    --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
    --prepend-as $INJ_AS --next-hop $INJ_IP --limit $LIMIT \
    --rate 0 --hold $HOLD"

one_run() { # side bin-dir run#
    local SIDE=$1 BINDIR=$2 RUN=$3
    local RUN_DIR="$OUT_DIR/side-$SIDE/run-$RUN"
    mkdir -p "$RUN_DIR"
    local SUT="ab-s15b-sut-$TS-$SIDE-$RUN" INJ="ab-s15b-inj-$TS-$SIDE-$RUN"
    trap 'docker rm -f "${SUT:-}" "${INJ:-}" >/dev/null 2>&1 || true' EXIT
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "==> side $SIDE run $RUN/$RUNS"
    start_sut "$SUT" "$BINDIR"
    start_injector "$INJ"
    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec "$INJ" ping -c1 -W2 "$SUT_IP" >/dev/null 2>&1 || true
    H=$(date +%s.%N); V=$(docker exec "$SUT" date +%s.%N); H2=$(date +%s.%N)
    python3 - "$H" "$V" "$H2" >"$RUN_DIR/clock-offset.txt" <<'EOF'
import sys
h1, v, h2 = (float(x) for x in sys.argv[1:4])
print(f"host_minus_vm={(h1+h2)/2-v:.6f} sampling_span={h2-h1:.6f}")
EOF
    docker exec "$SUT" getconf CLK_TCK > "$RUN_DIR/clk-tck.txt" 2>/dev/null || echo 100 > "$RUN_DIR/clk-tck.txt"

    echo "    launching poller + injector"
    python3 scripts/bench-poll.py \
        --sut-container "$SUT" --inj-container "$INJ" \
        --mode rouster --target-count "$LIMIT" --timeout "$TIMEOUT" \
        --csv "$RUN_DIR/poll.csv" > "$RUN_DIR/poller.log" 2>&1 &
    POLLER=$!
    sleep 2
    echo "$(date +%s.%N)" > "$RUN_DIR/injector-launch.txt"
    docker exec -d "$INJ" sh -c "mrt-replay $INJ_ARGS > /var/log/replay.txt 2>&1"

    if ! wait "$POLLER"; then
        echo "    POLLER FAILED (see $RUN_DIR/poller.log)" >&2
    fi
    wait_up "$INJ" "injector drained" 900 "grep -q REPLAY-LAST-UPDATE /var/log/replay.txt" || true

    # captures (E1 set + the allocator receipts)
    docker cp "$INJ:/var/log/replay.txt" "$RUN_DIR/injector.txt" 2>/dev/null || true
    docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
    docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
    docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
    docker exec "$SUT" sh -c "ip route show proto bgp | wc -l" > "$RUN_DIR/kernel-bgp-routes.txt" 2>&1 || true
    docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd | awk '{print \$1}')/stat /proc/\$(pidof rousterd | awk '{print \$1}')/stat" > "$RUN_DIR/final-proc-stat.txt" 2>/dev/null || true
    docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/status /proc/\$(pidof rousterd)/status" > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
    { echo "env: MIMALLOC_VERBOSE=1 (both sides; B=active receipt, A=negative control)";
      echo "mimalloc banner lines: $(grep -c mimalloc "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true)";
      grep -m4 mimalloc "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true; } > "$RUN_DIR/alloc-verify.txt"
    { echo "side=$SIDE"; shasum -a 256 "$BINDIR/bgpd"; } > "$RUN_DIR/bin-sha256.txt"
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "    artifacts: $RUN_DIR"
}

for SIDE in A B; do
    mkdir -p "$OUT_DIR/side-$SIDE"
done
# warmups first (image/container caching), then alternate the measured.
one_run A "$OUT_DIR/bin-A" 1
one_run B "$OUT_DIR/bin-B" 1
RUN2=$((RUNS < 2 ? 0 : 2))
if [ "$RUN2" -gt 1 ]; then
    # alternate: build the order A,B,A,B... for the remaining runs
    ORDER=""
    for RUN in $(seq 2 "$RUNS"); do
        ORDER="$ORDER A:$RUN B:$RUN"
    done
    for PAIR in $ORDER; do
        SIDE=${PAIR%%:*}; RUN=${PAIR##*:}
        one_run "$SIDE" "$OUT_DIR/bin-$SIDE" "$RUN"
    done
fi

# =========================================================================
# Phase 4 — summarize per side (shared summarizer) + the A/B fold
# =========================================================================
CLK=$(head -1 "$OUT_DIR/side-A/run-1/clk-tck.txt" 2>/dev/null || echo 100)
for SIDE in A B; do
    python3 scripts/bench-summarize.py --out-dir "$OUT_DIR/side-$SIDE" \
        --mode rouster --target-count "$LIMIT" --clk-tck "$CLK" \
        > "$OUT_DIR/side-$SIDE/summary.stdout" || true
done

python3 - "$OUT_DIR" > "$OUT_DIR/ab-fold.txt" <<'PYEOF'
import json, statistics, sys
from pathlib import Path

out = Path(sys.argv[1])

def per_run(side):
    runs = []
    for rj in sorted((out / f"side-{side}").glob("run-*/metrics.json")):
        runs.append(json.loads(rj.read_text()))
    return runs[1:] if len(runs) > 1 else runs  # run-1 = warmup

def bpdfx(m):
    fin, emp = m.get("sut_bgpd_rss_final_kb"), m.get("sut_bgpd_rss_empty_kb")
    pfx = m.get("main_prefixes_peak") or 0
    if fin is None or emp is None or not pfx:
        return None
    return (fin - emp) * 1024.0 / pfx

def med_p95(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return None, None
    p95 = statistics.quantiles(vals, n=20)[-1] if len(vals) >= 3 else max(vals)
    return statistics.median(vals), p95

fold = {"per_run": {}, "aggregate": {}}
KEYS = ["wall_external_s", "wall_bgp_level_s", "bgpd_cpu_s",
        "rousterd_cpu_s", "bgpd_rss_empty_kb", "bgpd_rss_final_kb",
        "bgpd_hwm_kb", "B_per_prefix"]
for side in ("A", "B"):
    runs = per_run(side)
    fold["per_run"][side] = [
        {"run": m["run"],
         "wall_external_s": m.get("wall_external_s"),
         "wall_bgp_level_s": m.get("wall_bgp_level_s"),
         "bgpd_cpu_s": m.get("sut_bgpd_cpu_s"),
         "rousterd_cpu_s": m.get("sut_zebra_cpu_s"),
         "bgpd_rss_empty_kb": m.get("sut_bgpd_rss_empty_kb"),
         "bgpd_rss_final_kb": m.get("sut_bgpd_rss_final_kb"),
         "bgpd_hwm_kb": m.get("sut_bgpd_hwm_kb"),
         "main_prefixes_peak": m.get("main_prefixes_peak"),
         "B_per_prefix": round(bpdfx(m), 2) if bpdfx(m) else None,
         "malformed": m.get("malformed"), "rejected": m.get("rejected"),
         "netlink_rcvbuf_overruns": m.get("netlink_rcvbuf_overruns")}
        for m in runs]
    agg = {}
    for k in KEYS:
        med, p95 = med_p95([r.get(k) for r in fold["per_run"][side]])
        if med is not None:
            agg[k] = {"median": round(med, 3), "p95": round(p95, 3)}
    fold["aggregate"][side] = agg

a, b = fold["aggregate"].get("A", {}), fold["aggregate"].get("B", {})
deltas = {}
if "B_per_prefix" in a and "B_per_prefix" in b:
    deltas["B_per_prefix_recovery_pct"] = round(
        (a["B_per_prefix"]["median"] - b["B_per_prefix"]["median"])
        / a["B_per_prefix"]["median"] * 100, 2)
for k in ("wall_external_s", "wall_bgp_level_s", "bgpd_cpu_s", "rousterd_cpu_s"):
    if k in a and k in b:
        deltas[k + "_delta_pct"] = round(
            (b[k]["median"] / a[k]["median"] - 1) * 100, 2)
fold["deltas_B_vs_A"] = deltas
(out / "ab-summary.json").write_text(json.dumps(fold, indent=1) + "\n")

print("=== A/B fold (medians [p95]; run-1 per side = warmup, excluded) ===")
for side in ("A", "B"):
    agg = fold["aggregate"].get(side, {})
    print(f"side {side}: " + "  ".join(
        f"{k}={v['median']}[{v['p95']}]" for k, v in agg.items()))
print("deltas B vs A: " + "  ".join(f"{k}={v}" for k, v in deltas.items()))
print("(descriptive fold only — the adopt/decline gate is applied in the"
      " docs/benchmarks.md §R entry, per the claim policy)")
PYEOF
cat "$OUT_DIR/ab-fold.txt"
echo "bench-alloc-ab: done — $OUT_DIR"
