#!/usr/bin/env bash
# bench-e1-ingest.sh — the E1 full-table BGP ingestion harness
# (docs/benchmarks.md §E1; program away/2026-10-15 BENCH-experiments).
#
# Modes:
#   gate     S0's D1 injector-headroom measurement: one rouster-side
#            run on a feed slice at unlimited injector rate.
#   rouster  S1: N runs (1 warmup + N-1 measured) of the full feed
#            into rouster bgpd + rousterd.
#   frr      S3: same shape with FRR 10.2.2 bgpd + zebra.
#
# Shape (§F): both SUT and injector are containers on bench-net
# (172.31.255.0/24, SUT .20, injector .10) with disjoint pinned CPUs.
# The injector is the in-repo mrt-replay tool (crates/bgpd/src/bin/)
# reading the raw MRT directly; docker/bench/ keeps the earlier
# exabgp artifacts (Dockerfile.exabgp, replay-driver.py) as the
# pre-switch record. Per-run evidence lands in
# target/bench-logs/<MODE>-<ts>/run-*/.
#
#   scripts/bench-e1-ingest.sh gate|rouster|frr <announce-file> [runs]
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: bench-e1-ingest.sh gate|rouster|frr <raw-mrt> [runs] [limit]}
# FEED is the RAW TABLE_DUMP_V2 MRT (bunzip2'd); LIMIT slices the
# first N prefixes (0 = the whole dump). The injector is the in-repo
# mrt-replay tool (D1(c) switch: exabgp measured ~36 msg/s sustained
# with deterministic hold-time death under bulk API - gate runs
# gate-20261015T050703Z / gate-20261015T051919Z).
FEED_MRT=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
RUNS=${3:-1}
FEED_LIMIT=${4:-0}
FEED_COUNT=$FEED_LIMIT
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
# Hold-time both session ends propose (negotiated = min). The Rouster
# runs use 900: bgpd's session loop can drop a completed read_frame
# when the keepalive timer wins a select! race (finding F7 — clean
# wire capture, tee-proxy evidence); a longer hold widens the KA
# interval and pacing (REPLAY_RATE) empties the race window. FRR runs
# keep 90 (unaffected).
HOLD=${BENCH_HOLD:-90}
TIMEOUT=${BENCH_TIMEOUT:-3600}

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *)             echo "unknown arch $(uname -m)" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/$MODE-$TS"
mkdir -p "$OUT_DIR"
echo "bench-e1-ingest: mode=$MODE feed=$FEED_MRT limit=$FEED_LIMIT (target $FEED_COUNT) runs=$RUNS"
echo "  sut cpus=$SUT_CPUS  injector cpus=$INJ_CPUS  rate=$REPLAY_RATE  out=$OUT_DIR"

# --- images -----------------------------------------------------------
perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
# Any leftover bench container would hold the fixed IPs (a killed
# harness run leaves no trap behind).
docker rm -f $(docker ps -aq --filter name=b1-) >/dev/null 2>&1 || true

# --- binaries (rouster modes need the musl build) ----------------------
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
echo "==> building rousterd + bgpd + rousterctl + mrt-replay ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd
cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd
cargo build --release --target "$MUSL_TARGET" -p bgpd --bin mrt-replay

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

start_sut_rouster() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" \
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
    docker exec -d "$1" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
    wait_up "$1" "rouster bgpd listening" 15 "grep -q 'bgpd: listening' /var/log/rouster-bgpd.log"
}

start_sut_frr() { # name — zebra + mgmtd + real bgpd, vtysh -b push
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$1" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
    docker exec "$1" sh -c "/usr/lib/frr/zebra -d --log file:/tmp/zebra.log --log-level info"
    wait_up "$1" "frr zebra vty" 30 "test -S /var/run/frr/zebra.vty"
    docker exec "$1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/tmp/mgmtd.log --log-level info"
    wait_up "$1" "frr mgmtd vty" 30 "test -S /var/run/frr/mgmtd.vty"
    docker exec "$1" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:/tmp/bgpd.log --log-level info"
    wait_up "$1" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
    docker exec "$1" sh -c "printf '%s\n' \
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
    local applied=0
    for _ in $(seq 1 10); do
        docker exec "$1" vtysh -b >/dev/null 2>&1 || true
        sleep 2
        if docker exec "$1" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP"; then
            applied=1; break
        fi
    done
    [ "$applied" = 1 ] || { echo "FAIL: FRR neighbor config never applied" >&2; return 1; }
    wait_up "$1" "frr bgpd bound :179" 30 "grep -qi '00B3' /proc/net/tcp"
}

start_injector() { # name - mrt-replay on the other pinned cpuset
    docker run -d --name "$1" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" \
        -v "$FEED_MRT":/feed.mrt:ro \
        --entrypoint sleep alpine:3.20 infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/mrt-replay" "$1:/usr/local/bin/mrt-replay"
    LIMIT_ARG=""
    [ "$FEED_LIMIT" != 0 ] && LIMIT_ARG="--limit $FEED_LIMIT"
    INJ_ARGS="--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
        --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
        --prepend-as $INJ_AS --next-hop $INJ_IP $LIMIT_ARG \
        --rate $REPLAY_RATE --hold $HOLD"
}

for run in $(seq 1 "$RUNS"); do
    RUN_DIR="$OUT_DIR/run-$run"
    mkdir -p "$RUN_DIR"
    SUT=b1-sut-$TS-$run
    INJ=b1-inj-$TS-$run
    trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "==> run $run/$RUNS"

    if [ "$MODE" = frr ]; then start_sut_frr "$SUT"; else start_sut_rouster "$SUT"; fi
    start_injector "$INJ"

    # ARP seeding (the M3 NHT gate wants lladdr before session start).
    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec "$INJ" ping -c1 -W2 "$SUT_IP" >/dev/null 2>&1 || true

    # Clock offset between the host observer and the VM (containers
    # share the darwin-vm kernel clock); recorded per run.
    H=$(date +%s.%N); V=$(docker exec "$SUT" date +%s.%N); H2=$(date +%s.%N)
    python3 - "$H" "$V" "$H2" >"$RUN_DIR/clock-offset.txt" <<'EOF'
import sys
h1, v, h2 = (float(x) for x in sys.argv[1:4])
print(f"host_minus_vm={(h1+h2)/2-v:.6f} sampling_span={h2-h1:.6f}")
EOF
    docker exec "$SUT" getconf CLK_TCK > "$RUN_DIR/clk-tck.txt" 2>/dev/null || echo 100 > "$RUN_DIR/clk-tck.txt"

    if [ "$MODE" = frr ]; then
        docker exec "$SUT" sh -c "vtysh -c 'show bgp neighbor $INJ_IP'" | head -20 > "$RUN_DIR/pre-run-neighbor.txt" || true
    fi

    echo "    launching poller + injector"
    python3 scripts/bench-poll.py \
        --sut-container "$SUT" --inj-container "$INJ" \
        --mode "$([ "$MODE" = frr ] && echo frr || echo rouster)" \
        --target-count "$FEED_COUNT" --timeout "$TIMEOUT" \
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

    # --- capture ------------------------------------------------------
    docker cp "$INJ:/var/log/replay.txt" "$RUN_DIR/injector.txt" 2>/dev/null || true
    if [ "$MODE" = frr ]; then
        for f in bgpd zebra mgmtd; do
            docker cp "$SUT:/tmp/$f.log" "$RUN_DIR/$f.log" 2>/dev/null || true
        done
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary'; vtysh -c 'show ip route summary'; ip route show proto bgp | wc -l" > "$RUN_DIR/final-vtysh.txt" 2>&1 || true
    else
        docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
        docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
        docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "ip route show proto bgp | wc -l" > "$RUN_DIR/kernel-bgp-routes.txt" 2>&1 || true
        docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd | awk '{print \$1}')/stat /proc/\$(pidof rousterd | awk '{print \$1}')/stat" > "$RUN_DIR/final-proc-stat.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "grep -Vm1 'VmHWM\|^$' /dev/null; cat /proc/\$(pidof rouster-bgpd)/status /proc/\$(pidof rousterd)/status" > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
    fi
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    echo "    run $run artifacts: $RUN_DIR"
done

CLK=$(head -1 "$OUT_DIR/run-1/clk-tck.txt" 2>/dev/null || echo 100)
python3 scripts/bench-summarize.py --out-dir "$OUT_DIR" --mode "$([ "$MODE" = frr ] && echo frr || echo rouster)" --target-count "$FEED_COUNT" --clk-tck "$CLK" || true
echo "bench-e1-ingest: done — $OUT_DIR/summary.json"
