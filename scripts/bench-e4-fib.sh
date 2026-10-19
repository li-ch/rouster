#!/usr/bin/env bash
# bench-e4-fib.sh — the E4 standalone FIB programming-rate harness
# (docs/benchmarks.md §E4; S14-b PERF-X stream).
#
# Shape (the pre-registered E4 entry + the 2026-10-16 protocol
# addendum): the SUT's RIB is loaded via the E1 shape (mrt-replay,
# single peer, unpaced, hold 90) at batch size B ∈ {1k, 10k, 100k};
# the measured pass is the FIB programming stream that follows
# (rousterd's pipelined route_replace_batch reconcile — the F8
# machinery), observed from a THIRD container that shares the SUT's
# network namespace but is pinned OFF the SUT cpuset, polling
# `ip route show proto 186 | wc -l` (the protocol's own observer
# placement, so the observer never burns SUT-pinned CPU).
#
# Per size B, per run: fresh SUT, kernel-count poll to completion
# (B − max(2, 0.5%) with a 3-row streak), then logs + /proc finals.
# Metrics (folded by bench-ex-summarize.py --e4): wall
# first-kernel-route→B-installed (the programming window) and
# launch→B-installed, routes/s, rousterd + bgpd CPU over the window,
# RSS of the pair, rcvbuf overruns, malformed/rejected.
#
# The FRR side is DERIVED, not re-run: zebra's own install rate from
# its ledgered full-table entry (9.67 CPU-s / 1,126,490 routes) per
# the stream prompt; the §R entry discloses the derivation.
#
#   scripts/bench-e4-fib.sh <raw-mrt> [runs]
# env: BENCH_E4_SIZES="1000 10000 100000", BENCH_E4_INTERVAL (poll
# seconds, default 0.15; 0.4 at 100k), plus the E1 rig knobs
# (BENCH_NET_NAME/SUBNET/SUT_IP/INJ_IP, BENCH_SUT_CPUS, BENCH_INJ_CPUS,
# BENCH_HOLD, BENCH_SUT_RMEM).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

FEED_MRT=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
RUNS=${2:-6}
SIZES=${BENCH_E4_SIZES:-"1000 10000 100000"}

SUT_AS=65000
INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
IMAGE=frr-testbed:10.2.2
SUT_CPUS=${BENCH_SUT_CPUS:-4-11}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
# Observer cpuset: MUST be disjoint from the SUT pins (the whole point
# of the third container). Default 12-17 (the rig's spare cores).
OBS_CPUS=${BENCH_E4_OBS_CPUS:-12-17}
HOLD=${BENCH_HOLD:-90}
# rouster (default): the F8 pipelined reconcile measured; frr: the
# same-run FRR comparator (zebra's own install stream) — the paper's
# cross-run-derivation caveat retires when this leg runs.
MODE=${BENCH_E4_MODE:-rouster}
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

# Prebuilt static binaries (BENCH_BIN_DIR) let the harness run on
# hosts without a Rust toolchain (e.g. the bare-metal bench boxes);
# unset, the paths reproduce the in-tree cargo layout.
BIN_DIR=${BENCH_BIN_DIR:-target/$MUSL_TARGET/release}

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/e4-$TS"
mkdir -p "$OUT_DIR"
echo "bench-e4-fib: mode=$MODE feed=$FEED_MRT sizes=[$SIZES] runs=$RUNS out=$OUT_DIR"

docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
# Probe on the run network: some hosts lack the default docker0
# while daemon-created custom bridges work (the bench boxes).
perl -e 'alarm 15; exec @ARGV' docker run --rm --network "$NET_NAME" --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker rm -f $(docker ps -aq --filter name=e4x-) >/dev/null 2>&1 || true


docker ps --format '{{.Names}}' > "$OUT_DIR/docker-ps-snapshot.txt" 2>/dev/null || true

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

for SIZE in $SIZES; do
    INTERVAL=${BENCH_E4_INTERVAL:-}
    if [ -z "$INTERVAL" ]; then
        INTERVAL=0.15
        [ "$SIZE" -ge 100000 ] && INTERVAL=0.4
    fi
    for run in $(seq 1 "$RUNS"); do
        RUN_DIR="$OUT_DIR/size-$SIZE/run-$run"
        mkdir -p "$RUN_DIR"
        SUT=e4x-sut-$TS-$SIZE-$run
        INJ=e4x-inj-$TS-$SIZE-$run
        OBS=e4x-obs-$TS-$SIZE-$run
        trap 'docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true' EXIT
        docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true
        echo "==> size $SIZE run $run/$RUNS (interval ${INTERVAL}s)"

        # --- SUT: rousterd + bgpd (the E1 rig, sysctls included) -----
        docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
            --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
            --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        if [ "$MODE" = frr ]; then
            # The FRR comparator: zebra's own install stream, same rig,
            # same observer, same counting basis (proto 186).
            docker exec "$SUT" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
            docker exec "$SUT" sh -c "/usr/lib/frr/zebra -d --log file:/tmp/zebra.log --log-level info"
            for _ in $(seq 1 30); do docker exec "$SUT" sh -c "test -S /var/run/frr/zebra.vty" >/dev/null 2>&1 && break; sleep 1; done
            docker exec "$SUT" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/tmp/mgmtd.log --log-level info"
            docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:/tmp/bgpd.log --log-level info"
            for _ in $(seq 1 30); do docker exec "$SUT" sh -c "test -S /var/run/frr/bgpd.vty" >/dev/null 2>&1 && break; sleep 1; done
            docker exec "$SUT" sh -c "printf '%s\n' \
                'frr version 10.2' \
                'frr defaults traditional' \
                'hostname bench-e4-frr' \
                'router bgp $SUT_AS' \
                ' no bgp network import-check' \
                ' no bgp ebgp-requires-policy' \
                ' neighbor $INJ_IP remote-as $INJ_AS' \
                ' neighbor $INJ_IP timers 30 $HOLD' \
                ' address-family ipv4 unicast' \
                '  exit-address-family' \
                'line vty' \
                > /etc/frr/frr.conf"
            for _ in $(seq 1 10); do
                docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
                sleep 2
                docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP" && break
            done
            docker exec "$SUT" sh -c "grep -qi '00B3' /proc/net/tcp"
        fi
        if [ "$MODE" != frr ]; then
        for b in rousterd rousterctl; do
            docker cp "$BIN_DIR/$b" "$SUT:/usr/local/bin/$b"
        done
        docker cp "$BIN_DIR/bgpd" "$SUT:/usr/local/bin/rouster-bgpd"
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

        # --- the third-container observer (shares SUT netns, own pins).
        # The kernel-count loop runs INSIDE this container (a tight
        # `ip route show proto 186 | grep -c .` loop on the observer's
        # cpuset, rows "<epoch_ns> <count>" host-visible via the volume)
        # — the host-side docker-exec cadence (~3-7 Hz) is coarser than
        # the 1k-10k programming pass itself; the in-container loop
        # resolves it (the dump's own RTNL cost is disclosed).
        NEED=$(( SIZE - (SIZE / 200 > 2 ? SIZE / 200 : 2) ))
        RUN_DIR_ABS=$(cd "$RUN_DIR" && pwd)
        docker run -d --name "$OBS" --network "container:$SUT" \
            --cpuset-cpus "$OBS_CPUS" \
            -v "$RUN_DIR_ABS":/obs \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        base=$(docker exec "$OBS" sh -c "ip route show proto 186 2>/dev/null | grep -c ." || echo 0)
        echo "$base" > "$RUN_DIR/kernel-baseline.txt"
        docker exec -d -e TARGET="$NEED" -e MAXS=900 "$OBS" bash -c '
            : > /obs/poll.csv
            end=$(( $(date +%s) + MAXS )); stable=0
            while :; do
                n=$(ip route show proto 186 2>/dev/null | grep -c .)
                echo "$EPOCHREALTIME $n" >> /obs/poll.csv
                if [ "$n" -ge "$TARGET" ] 2>/dev/null; then
                    stable=$((stable + 1)); [ "$stable" -ge 5 ] && break
                else
                    stable=0
                fi
                [ "$(date +%s)" -gt "$end" ] && break
                sleep 0.02
            done'

        # --- injector ---------------------------------------------------
        docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" \
            -v "$FEED_MRT":/feed.mrt:ro \
            --entrypoint sleep alpine:3.20 infinity >/dev/null
        docker cp "$BIN_DIR/mrt-replay" "$INJ:/usr/local/bin/mrt-replay"
        INJ_ARGS="--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
            --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
            --prepend-as $INJ_AS --next-hop $INJ_IP --limit $SIZE \
            --rate 0 --hold $HOLD"

        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec "$INJ" ping -c1 -W2 "$SUT_IP" >/dev/null 2>&1 || true

        # clock offset (E1 practice)
        H=$(date +%s.%N); V=$(docker exec "$SUT" date +%s.%N); H2=$(date +%s.%N)
        python3 - "$H" "$V" "$H2" >"$RUN_DIR/clock-offset.txt" <<'EOF'
import sys
h1, v, h2 = (float(x) for x in sys.argv[1:4])
print(f"host_minus_vm={(h1+h2)/2-v:.6f} sampling_span={h2-h1:.6f}")
EOF
        docker exec "$SUT" getconf CLK_TCK > "$RUN_DIR/clk-tck.txt" 2>/dev/null || echo 100 > "$RUN_DIR/clk-tck.txt"

        echo "$INJ_ARGS" > "$RUN_DIR/injector-args.txt"
        echo "    launching observer + injector"
        T_LAUNCH=$(date +%s.%N)
        echo "$T_LAUNCH" > "$RUN_DIR/injector-launch.txt"
        HOST_MINUS_VM=$(sed -n 's/.*host_minus_vm=\([0-9.-]*\).*/\1/p' "$RUN_DIR/clock-offset.txt")
        python3 scripts/bench-observe.py \
            --sut-container "$SUT" --kernel-container "$OBS" \
            --mode "$MODE" --interval "$INTERVAL" --timeout 900 \
            --complete-on kernel --target-count "$SIZE" --streak 3 \
            --settle 15 --proc-every 3 --stall-after 120 \
            --poll-file "$RUN_DIR/poll.csv" \
            --poll-clock-offset "$HOST_MINUS_VM" \
            --csv "$RUN_DIR/observe.csv" > "$RUN_DIR/observer.log" 2>&1 &
        OBSERVER=$!
        sleep 2
        docker exec -d "$INJ" sh -c "mrt-replay $INJ_ARGS > /var/log/replay.txt 2>&1"
        if ! wait "$OBSERVER"; then
            echo "    OBSERVER FAILED (see $RUN_DIR/observer.log)" >&2
        fi

        # --- capture ----------------------------------------------------
        docker cp "$INJ:/var/log/replay.txt" "$RUN_DIR/injector.txt" 2>/dev/null || true
        if [ "$MODE" = frr ]; then
            for fl in bgpd zebra mgmtd; do
                docker cp "$SUT:/tmp/$fl.log" "$RUN_DIR/$fl.log" 2>/dev/null || true
            done
        fi
        docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
        docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
        docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/stat /proc/\$(pidof rousterd)/stat" \
            > "$RUN_DIR/final-proc-stat.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/status /proc/\$(pidof rousterd)/status" \
            > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
        docker exec "$OBS" sh -c "ip route show proto 186 | grep -c ." \
            > "$RUN_DIR/final-kernel-count.txt" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" "$OBS" >/dev/null 2>&1 || true
        echo "    run $run artifacts: $RUN_DIR"
    done
done

CLK=$(head -1 "$OUT_DIR/size-$(echo $SIZES | awk '{print $1}')/run-1/clk-tck.txt" 2>/dev/null || echo 100)
for SIZE in $SIZES; do
    python3 scripts/bench-ex-summarize.py --e4 \
        --out-dir "$OUT_DIR/size-$SIZE" --target-count "$SIZE" --clk-tck "$CLK"
done
echo "bench-e4-fib: done — $OUT_DIR"
