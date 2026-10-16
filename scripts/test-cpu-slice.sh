#!/usr/bin/env bash
# test-cpu-slice.sh — the PERF-P2 CPU-campaign receipt runner
# (away/2026-10-16 PERF-P2; the E1 protocol scaled to a feed slice).
#
# Same shape as scripts/test-bgp-mem-slice.sh (PERF-M1's runner —
# reused read-only, never modified): bench-net topology, pinned cpus,
# the in-repo mrt-replay injector, the bench-poll.py observer whose
# CSV carries the per-second CPU-jiffies series. Two modes:
#
#   clean   build WITHOUT the cpu-census feature (byte-comparable
#           with the §R E1 runs) — the headline CPU/wall receipts.
#   census  build WITH --features rousterd/cpu-census and start
#           rousterd with ROUSTERD_CPU_CENSUS=1 — the phase table,
#           appended to /run/rouster/rousterd.status (additive lines;
#           sampled 1 Hz to samples/ so the ingest window and the
#           post-settle ticks are separable). The timers' own cost is
#           disclosed by rd_status_publish.
#
#   scripts/test-cpu-slice.sh clean|census <raw-mrt> <limit> [runs]
#   limit 0 = the full feed (the wall/CPU receipt).
#
# Ablation knob (the census's logging attribution): ROUSTERD_LOG
# (trace|debug|info|warn|error) passes through to the daemon; run
# `ROUSTERD_LOG=warn scripts/test-cpu-slice.sh clean ...` to measure
# the per-route info lines' share.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: test-cpu-slice.sh clean|census <raw-mrt> <limit> [runs]}
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
OUT_DIR="target/cpu-logs/$MODE-$TS"
mkdir -p "$OUT_DIR"
echo "cpu-slice: mode=$MODE feed=$FEED_MRT limit=$LIMIT (target $FEED_COUNT) runs=$RUNS"
echo "  sut cpus=$SUT_CPUS  injector cpus=$INJ_CPUS  rate=$REPLAY_RATE  out=$OUT_DIR"
[ -n "${ROUSTERD_LOG:-}" ] && echo "  ROUSTERD_LOG=$ROUSTERD_LOG (ablation)"

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=p2-) >/dev/null 2>&1 || true

if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
FEATURE_ARGS=()
[ "$MODE" = census ] && FEATURE_ARGS=(--features rousterd/cpu-census)
echo "==> building rousterd + bgpd + rousterctl + mrt-replay ($MUSL_TARGET, release, features=${FEATURE_ARGS[*]:-none})"
cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd ${FEATURE_ARGS[@]+"${FEATURE_ARGS[@]}"}
cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin mrt-replay

# P0-b harness parity (commit 9131271): the SUT container gets a
# large netlink receive buffer — rousterd's netlink socket subscribes
# to the route multicast groups, so the install storm's notification
# echoes overrun the default rcvbuf (ENOBUFS); dropped ACKs hang
# netlink-proto's timeout-less request futures and freeze the install
# pipeline. Mirrors bench-e1-ingest.sh symmetrically; BENCH_SUT_RMEM=0
# disables for A/B runs.
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
    # census mode arms the timers via the env var; the ablation's
    # ROUSTERD_LOG rides along in both modes.
    CENSUS_ENV=(-e ROUSTERD_LOG="${ROUSTERD_LOG:-info}")
    [ "$MODE" = census ] && CENSUS_ENV+=(-e ROUSTERD_CPU_CENSUS=1)
    docker exec -d ${CENSUS_ENV[@]+"${CENSUS_ENV[@]}"} "$1" sh -c \
        "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
    # Socket-based wait (not the log line): the ablation runs with
    # ROUSTERD_LOG=warn, which suppresses the info-level startup lines.
    wait_up "$1" "rousterd zapi socket bound" 30 "test -S /run/rouster/zserv.api"
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /run/rouster/zserv.api' \
        'router bgp $SUT_AS' \
        ' bgp router-id $SUT_IP' \
        ' neighbor $INJ_IP remote-as $INJ_AS' \
        ' neighbor $INJ_IP passive' \
        ' hold-time $HOLD' \
        > /etc/rouster-bgp.conf"
    docker exec "$1" sh -c "rouster-bgpd --validate-config /etc/rouster-bgp.conf"
    docker exec -d "$1" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
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
    mkdir -p "$RUN_DIR/samples"
    SUT=p2-sut-$TS-$run
    INJ=p2-inj-$TS-$run
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

    # 1 Hz census-snapshot sampler: the status file between the
    # injector start and the poller's end (census rows are cumulative;
    # the series separates the ingest window from the post-settle
    # ticks). Cheap (one small cat per second).
    (
        while :; do
            docker exec "$SUT" sh -c \
                "cat /run/rouster/rousterd.status 2>/dev/null" \
                > "$RUN_DIR/samples/status-$(date +%s).txt" 2>/dev/null || true
            sleep 1
            # exit when the SUT is gone (the run's teardown beat us)
            docker inspect "$SUT" >/dev/null 2>&1 || break
        done
    ) &
    SAMPLER=$!

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
    kill "$SAMPLER" 2>/dev/null || true
    wait "$SAMPLER" 2>/dev/null || true
    wait_up "$INJ" "injector drained" 3600 "grep -q REPLAY-LAST-UPDATE /var/log/replay.txt" || true

    docker cp "$INJ:/var/log/replay.txt" "$RUN_DIR/injector.txt" 2>/dev/null || true
    docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
    docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
    docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
    docker exec "$SUT" sh -c "ip route show proto bgp | wc -l" > "$RUN_DIR/kernel-bgp-routes.txt" 2>&1 || true
    docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/status /proc/\$(pidof rousterd)/status" > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
    docker exec "$SUT" sh -c "awk '{print \$14, \$15}' /proc/\$(pidof rousterd)/stat" > "$RUN_DIR/final-rousterd-jiffies.txt" 2>/dev/null || true
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "    run $run artifacts: $RUN_DIR"
done

CLK=$(head -1 "$OUT_DIR/run-1/clk-tck.txt" 2>/dev/null || echo 100)
python3 scripts/bench-summarize.py --out-dir "$OUT_DIR" --mode rouster --target-count "$FEED_COUNT" --clk-tck "$CLK" || true
echo "cpu-slice: done — $OUT_DIR/summary.json"
