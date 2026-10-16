#!/usr/bin/env bash
# bench-e2-churn.sh — the E2 churn/reconvergence harness
# (docs/benchmarks.md §E2; S14-b PERF-X stream).
#
# Shape (the pre-registered E2 entry + the 2026-10-16 protocol
# addendum): the table is loaded over one eBGP session by
# scripts/bench-flap.py (the mrt-replay announce file — same feed,
# same NEXT_HOP/AS-path surgery, same packing; the flap tool adds
# only the withdraw/reannounce capability), then R rounds of
# withdraw+reannounce over a fixed subset (every Nth prefix = 10% of
# the table at --flap-every 10). The observer (bench-observe.py)
# records the SUT's own table count + the kernel FIB count (from a
# third container sharing the SUT netns, pinned off the SUT cpuset)
# + per-daemon CPU/RSS through the storm. The summarizer computes
# per-round reconvergence walls (reannounce-done → count restored).
#
# BOTH SIDES run the identical injector with the identical schedule
# (the §F fairness rule — the injector actions are the same bytes on
# both SUTs; no vtysh-side clear, which only one side could do
# identically).
#
#   scripts/bench-e2-churn.sh rouster|frr <announce-file> [runs]
# env: BENCH_E2_LIMIT (100000) BENCH_E2_FLAP_EVERY (10)
#      BENCH_E2_ROUNDS (10) BENCH_E2_STEADY (15) BENCH_E2_ROUND_GAP (2)
#      BENCH_E2_DEADLINE (300) + the E1 rig knobs.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: bench-e2-churn.sh rouster|frr <announce-file> [runs]}
ANNOUNCE=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
RUNS=${3:-6}
LIMIT=${BENCH_E2_LIMIT:-100000}
FLAP_EVERY=${BENCH_E2_FLAP_EVERY:-10}
ROUNDS=${BENCH_E2_ROUNDS:-10}
STEADY=${BENCH_E2_STEADY:-15}
ROUND_GAP=${BENCH_E2_ROUND_GAP:-2}
DEADLINE=${BENCH_E2_DEADLINE:-300}

SUT_AS=65000
INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
IMAGE=frr-testbed:10.2.2
# The injector base carries python3 for bench-flap.py. docker.io was
# unreachable from this rig (registry Bad Gateway), so the pinned
# bench-exabgp:local image (docker/bench/Dockerfile.exabgp — the D1
# pre-switch record, Python 3.12 inside) is repurposed as the flap
# driver's base; the harness pins its tag in the entry.
INJ_IMAGE=${BENCH_E2_INJ_IMAGE:-bench-exabgp:local}
SUT_CPUS=${BENCH_SUT_CPUS:-4-11}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
OBS_CPUS=${BENCH_E2_OBS_CPUS:-12-17}
HOLD=${BENCH_HOLD:-90}
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
OUT_DIR="target/bench-logs/e2-$TS"
mkdir -p "$OUT_DIR"
echo "bench-e2-churn: mode=$MODE announce=$ANNOUNCE limit=$LIMIT flap-every=$FLAP_EVERY"
echo "  rounds=$ROUNDS runs=$RUNS out=$OUT_DIR"

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=e2x-) >/dev/null 2>&1 || true

if [ "$MODE" = rouster ]; then
    if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
        rustup target add "$MUSL_TARGET"
    fi
    echo "==> building rousterd + bgpd ($MUSL_TARGET, release)"
    cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd
    cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
    cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd
fi
docker ps --format '{{.Names}}' > "$OUT_DIR/docker-ps-snapshot.txt" 2>/dev/null || true

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

for run in $(seq 1 "$RUNS"); do
    RUN_DIR="$OUT_DIR/run-$run"
    mkdir -p "$RUN_DIR"
    SUT=e2x-sut-$TS-$run
    INJ=e2x-inj-$TS-$run
    OBS=e2x-obs-$TS-$run
    trap 'docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true' EXIT
    docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true
    echo "==> run $run/$RUNS"

    # --- SUT ------------------------------------------------------------
    if [ "$MODE" = frr ]; then
        docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
            --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
            --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        docker exec "$SUT" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
        docker exec "$SUT" sh -c "/usr/lib/frr/zebra -d --log file:/tmp/zebra.log --log-level info"
        wait_up "$SUT" "frr zebra vty" 30 "test -S /var/run/frr/zebra.vty"
        docker exec "$SUT" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/tmp/mgmtd.log --log-level info"
        wait_up "$SUT" "frr mgmtd vty" 30 "test -S /var/run/frr/mgmtd.vty"
        docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:/tmp/bgpd.log --log-level info"
        wait_up "$SUT" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'frr version 10.2' \
            'frr defaults traditional' \
            'hostname bench-frr' \
            'router bgp 65000' \
            ' no bgp network import-check' \
            ' no bgp ebgp-requires-policy' \
            ' neighbor $INJ_IP remote-as $INJ_AS' \
            ' neighbor $INJ_IP timers 30 $HOLD' \
            ' address-family ipv4 unicast' \
            '  exit-address-family' \
            'line vty' \
            > /etc/frr/frr.conf"
        local_applied=0
        for _ in $(seq 1 10); do
            docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
            sleep 2
            if docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP"; then
                local_applied=1; break
            fi
        done
        [ "$local_applied" = 1 ] || { echo "FAIL: FRR neighbor config never applied" >&2; exit 1; }
        wait_up "$SUT" "frr bgpd bound :179" 30 "grep -qi '00B3' /proc/net/tcp"
    else
        docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
            --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
            --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        for b in rousterd rousterctl; do
            docker cp "target/$MUSL_TARGET/release/$b" "$SUT:/usr/local/bin/$b"
        done
        docker cp "target/$MUSL_TARGET/release/bgpd" "$SUT:/usr/local/bin/rouster-bgpd"
        docker exec "$SUT" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'zapi socket /run/rouster/zserv.api' > /etc/rouster.conf"
        docker exec -d "$SUT" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
        wait_up "$SUT" "rousterd zapi listening" 30 "grep -q 'zapi: listening' /var/log/rousterd.log"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'zapi socket /run/rouster/zserv.api' \
            'router bgp $SUT_AS' \
            ' bgp router-id $SUT_IP' \
            ' neighbor $INJ_IP remote-as $INJ_AS' \
            ' neighbor $INJ_IP passive' \
            ' hold-time $HOLD' \
            > /etc/rouster-bgp.conf"
        docker exec "$SUT" sh -c "rouster-bgpd --validate-config /etc/rouster-bgp.conf"
        docker exec -d "$SUT" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
        wait_up "$SUT" "rouster bgpd listening" 15 "grep -q 'bgpd: listening' /var/log/rouster-bgpd.log"
    fi

    # --- observer container (shares SUT netns, off the SUT pins) --------
    # Same high-resolution trick as E4: the kernel-count loop runs
    # INSIDE the observer container (off the SUT pins), rows
    # host-visible via the volume; it stops on the run's STOP file
    # (the storm's count legitimately dips mid-run, so completion is
    # harness-driven, not count-driven).
    RUN_DIR_ABS=$(cd "$RUN_DIR" && pwd)
    docker run -d --name "$OBS" --network "container:$SUT" \
        --cpuset-cpus "$OBS_CPUS" \
        -v "$RUN_DIR_ABS":/obs \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$OBS" sh -c "ip route show proto 186 2>/dev/null | grep -c ." \
        > "$RUN_DIR/kernel-baseline.txt" 2>/dev/null || echo 0 > "$RUN_DIR/kernel-baseline.txt"
    rm -f "$RUN_DIR/STOP"
    docker exec -d "$OBS" bash -c '
        : > /obs/poll.csv
        while [ ! -e /obs/STOP ]; do
            n=$(ip route show proto 186 2>/dev/null | grep -c .)
            echo "$EPOCHREALTIME $n" >> /obs/poll.csv
            sleep 0.05
        done'

    # --- injector: bench-flap.py on its own pinned container ------------
    docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" \
        -v "$ANNOUNCE":/feed.announce:ro \
        --entrypoint sleep "$INJ_IMAGE" infinity >/dev/null
    docker cp scripts/bench-flap.py "$INJ:/bench-flap.py"
    FLAP_ARGS="--peer $SUT_IP:179 --local-as $INJ_AS --peer-as $SUT_AS \
        --router-id $INJ_IP --announce /feed.announce --limit $LIMIT \
        --flap-every $FLAP_EVERY --rounds $ROUNDS --hold $HOLD \
        --steady-wait $STEADY --round-gap $ROUND_GAP"
    echo "$FLAP_ARGS" > "$RUN_DIR/injector-args.txt"

    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec "$INJ" ping -c1 -W2 "$SUT_IP" >/dev/null 2>&1 || true

    H=$(date +%s.%N); V=$(docker exec "$SUT" date +%s.%N); H2=$(date +%s.%N)
    python3 - "$H" "$V" "$H2" >"$RUN_DIR/clock-offset.txt" <<'EOF'
import sys
h1, v, h2 = (float(x) for x in sys.argv[1:4])
print(f"host_minus_vm={(h1+h2)/2-v:.6f} sampling_span={h2-h1:.6f}")
EOF
    docker exec "$SUT" getconf CLK_TCK > "$RUN_DIR/clk-tck.txt" 2>/dev/null || echo 100 > "$RUN_DIR/clk-tck.txt"

    echo "    launching observer + flap injector"
    STOP_FILE="$RUN_DIR/STOP"
    rm -f "$STOP_FILE"
    python3 scripts/bench-observe.py \
        --sut-container "$SUT" --kernel-container "$OBS" --inj-container "$INJ" \
        --mode "$MODE" --interval 0.3 --timeout $((DEADLINE + 600)) \
        --complete-on none --stop-file "$STOP_FILE" --proc-every 3 \
        --csv "$RUN_DIR/observe.csv" > "$RUN_DIR/observer.log" 2>&1 &
    OBSERVER=$!
    sleep 2
    T_LAUNCH=$(date +%s.%N)
    echo "$T_LAUNCH" > "$RUN_DIR/injector-launch.txt"
    docker exec -d "$INJ" sh -c "python3 /bench-flap.py $FLAP_ARGS > /var/log/flap.txt 2>&1"

    # Wait for the flap tool's terminal line, then release the observer.
    DONE_MARK="FLAP-LINGER-END"
    ABORT_MARKS="FLAP-ABORT FLAP-ERROR"
    t0=$(date +%s)
    while :; do
        if docker exec "$INJ" sh -c "grep -qE '$DONE_MARK|$ABORT_MARKS' /var/log/flap.txt" 2>/dev/null; then
            break
        fi
        if [ $(( $(date +%s) - t0 )) -gt "$DEADLINE" ]; then
            echo "    FLAP DEADLINE exceeded (${DEADLINE}s) — stopping run" >&2
            break
        fi
        sleep 2
    done
    sleep 3   # trailing observer rows
    touch "$STOP_FILE"
    if ! wait "$OBSERVER" 2>/dev/null; then
        echo "    observer exited nonzero (see $RUN_DIR/observer.log)" >&2
    fi

    # --- capture --------------------------------------------------------
    docker cp "$INJ:/var/log/flap.txt" "$RUN_DIR/flap.txt" 2>/dev/null || true
    if [ "$MODE" = frr ]; then
        for f in bgpd zebra mgmtd; do
            docker cp "$SUT:/tmp/$f.log" "$RUN_DIR/$f.log" 2>/dev/null || true
        done
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary'; vtysh -c 'show ip route summary'" \
            > "$RUN_DIR/final-vtysh.txt" 2>&1 || true
    else
        docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
        docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
        docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
    fi
    docker exec "$OBS" sh -c "ip route show proto 186 | grep -c ." \
        > "$RUN_DIR/final-kernel-count.txt" 2>/dev/null || true
    docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true
    echo "    run $run artifacts: $RUN_DIR"
done

CLK=$(head -1 "$OUT_DIR/run-1/clk-tck.txt" 2>/dev/null || echo 100)
python3 scripts/bench-ex-summarize.py --e2 --mode "$MODE" \
    --out-dir "$OUT_DIR" --target-count "$LIMIT" --clk-tck "$CLK" \
    --flap-every "$FLAP_EVERY" --rounds "$ROUNDS"
echo "bench-e2-churn: done — $OUT_DIR"
