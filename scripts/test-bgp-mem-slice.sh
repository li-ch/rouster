#!/usr/bin/env bash
# test-bgp-mem-slice.sh — the PERF-M1 memory-campaign receipt runner
# (away/2026-10-16 PERF-M1; the E1 protocol scaled to a feed slice).
#
# Same shape as scripts/bench-e1-ingest.sh (P0's harness — reused
# read-only, never modified): bench-net topology, pinned cpus, the
# in-repo mrt-replay injector, the bench-poll.py observer whose CSV
# carries the per-second RSS series (E5). Two modes:
#
#   clean   build WITHOUT the mem-census feature (byte-comparable
#           with the §R E1 runs) — the headline RSS/wall/CPU numbers.
#   census  build WITH --features bgpd/mem-census and start bgpd with
#           BGPD_MEM_CENSUS=1 — the per-structure census table (its
#           own RSS is perturbed by the walk; disclosed per run).
#
#   scripts/test-bgp-mem-slice.sh clean|census <raw-mrt> <limit> [runs]
#   limit 0 = the full feed (the wall/CPU receipt).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: test-bgp-mem-slice.sh clean|census <raw-mrt> <limit> [runs]}
FEED_MRT=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
LIMIT=${3:?limit (0 = full feed)}
RUNS=${4:-1}
FEED_COUNT=$LIMIT
if [ "$FEED_COUNT" = 0 ]; then
    FEED_COUNT=1126490 # route-views2 rib.20261015.0400 ipv4-unicast prefixes
fi

SUT_AS=65000
INJ_AS=65412
SUT_IP=172.31.255.20
INJ_IP=172.31.255.10
NET_NAME=bench-net
NET_SUBNET=172.31.255.0/24
IMAGE=frr-testbed:10.2.2
SUT_CPUS=${BENCH_SUT_CPUS:-4-11}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
REPLAY_RATE=${BENCH_REPLAY_RATE:-0}
HOLD=${BENCH_HOLD:-90}
TIMEOUT=${BENCH_TIMEOUT:-3600}
SETTLE=${BENCH_SETTLE:-30}

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *)             echo "unknown arch $(uname -m)" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/mem-logs/$MODE-$TS"
mkdir -p "$OUT_DIR"
echo "mem-slice: mode=$MODE feed=$FEED_MRT limit=$LIMIT (target $FEED_COUNT) runs=$RUNS"
echo "  sut cpus=$SUT_CPUS  injector cpus=$INJ_CPUS  rate=$REPLAY_RATE  out=$OUT_DIR"

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=m1-) >/dev/null 2>&1 || true

if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
FEATURE_ARGS=()
[ "$MODE" = census ] && FEATURE_ARGS=(--features bgpd/mem-census)
echo "==> building rousterd + bgpd + rousterctl + mrt-replay ($MUSL_TARGET, release, features=${FEATURE_ARGS[*]:-none})"
cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd
cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin mrt-replay

# P0-b harness parity (commit 9131271): the SUT container gets a
# large netlink receive buffer — rousterd's netlink socket is
# subscribed to the route multicast groups, so the full-table install
# storm's notification echoes overrun the default rcvbuf (ENOBUFS);
# dropped ACKs hang netlink-proto's timeout-less request futures and
# freeze the install pipeline (observed once here: a full-feed run
# wedged at 584,208 of 1,126,481 installs). Mirrors bench-e1-ingest.sh
# symmetrically; BENCH_SUT_RMEM=0 disables for A/B runs.
SUT_RMEM=${BENCH_SUT_RMEM:-33554432}
SUT_SYSCTLS=""
if [ "$SUT_RMEM" != 0 ]; then
    SUT_SYSCTLS="--sysctl net.core.rmem_default=$SUT_RMEM --sysctl net.core.rmem_max=$((SUT_RMEM * 2))"
fi

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

start_sut() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    for b in rousterd rousterctl; do
        docker cp "target/$MUSL_TARGET/release/$b" "$1:/usr/local/bin/$b"
    done
    docker cp "target/$MUSL_TARGET/release/bgpd" "$1:/usr/local/bin/rouster-bgpd"
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
    # census mode: the env var reaches the daemon via docker exec -e.
    CENSUS_ENV=()
    [ "$MODE" = census ] && CENSUS_ENV=(-e BGPD_MEM_CENSUS=1)
    docker exec -d ${CENSUS_ENV[@]+"${CENSUS_ENV[@]}"} "$1" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
    wait_up "$1" "rouster bgpd listening" 15 "grep -q 'bgpd: listening' /var/log/rouster-bgpd.log"
}

start_injector() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" \
        -v "$FEED_MRT":/feed.mrt:ro \
        --entrypoint sleep alpine:3.20 infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/mrt-replay" "$1:/usr/local/bin/mrt-replay"
    LIMIT_ARG=""
    [ "$LIMIT" != 0 ] && LIMIT_ARG="--limit $LIMIT"
    INJ_ARGS="--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
        --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
        --prepend-as $INJ_AS --next-hop $INJ_IP $LIMIT_ARG \
        --rate $REPLAY_RATE --hold $HOLD"
}

for run in $(seq 1 "$RUNS"); do
    RUN_DIR="$OUT_DIR/run-$run"
    mkdir -p "$RUN_DIR"
    SUT=m1-sut-$TS-$run
    INJ=m1-inj-$TS-$run
    trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "==> run $run/$RUNS"

    start_sut "$SUT"
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
        --mode rouster \
        --target-count "$FEED_COUNT" --timeout "$TIMEOUT" --settle "$SETTLE" \
        --csv "$RUN_DIR/poll.csv" > "$RUN_DIR/poller.log" 2>&1 &
    POLLER=$!
    sleep 2
    T_LAUNCH=$(date +%s.%N)
    echo "$T_LAUNCH" > "$RUN_DIR/injector-launch.txt"
    docker exec -d "$INJ" sh -c "mrt-replay $INJ_ARGS > /var/log/replay.txt 2>&1"

    if ! wait "$POLLER"; then
        echo "    POLLER FAILED (see $RUN_DIR/poller.log)" >&2
    fi
    wait_up "$INJ" "injector drained" 3600 "grep -q REPLAY-LAST-UPDATE /var/log/replay.txt" || true

    docker cp "$INJ:/var/log/replay.txt" "$RUN_DIR/injector.txt" 2>/dev/null || true
    docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
    docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
    docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
    docker exec "$SUT" sh -c "ip route show proto bgp | wc -l" > "$RUN_DIR/kernel-bgp-routes.txt" 2>&1 || true
    docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/status /proc/\$(pidof rousterd)/status" > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "    run $run artifacts: $RUN_DIR"
done

CLK=$(head -1 "$OUT_DIR/run-1/clk-tck.txt" 2>/dev/null || echo 100)
python3 scripts/bench-summarize.py --out-dir "$OUT_DIR" --mode rouster --target-count "$FEED_COUNT" --clk-tck "$CLK" || true
echo "mem-slice: done — $OUT_DIR/summary.json"
