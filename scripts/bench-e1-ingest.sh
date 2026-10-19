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
#   hybrid   config B (the rewrite plan's E2-configB): the SAME FRR
#            10.2.2 bgpd (with mgmtd) speaking against the ROUSTER
#            core (rousterd) as its zebra — isolates core
#            replacement. Poller mode 'hybrid': the main-table oracle
#            is rousterd's status file (symmetric with config D) and
#            the BGP-level curve comes from vtysh pfxRcd.
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

MODE=${1:?usage: bench-e1-ingest.sh gate|rouster|frr|hybrid <raw-mrt> [runs] [limit]}
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
# Rig placement is env-overridable so sibling campaign streams can run
# concurrently (PERF-P0/PERF-M1 share this host): each session takes
# its own bridge + subnet via BENCH_NET_NAME/BENCH_NET_SUBNET and the
# matching SUT/injector IPs. Defaults reproduce the original rig
# exactly (bench-net 172.31.255.0/24) — §F's same-host/same-engine
# fairness is unaffected (a fresh private bridge per session).
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
IMAGE=frr-testbed:10.2.2
SUT_CPUS=${BENCH_SUT_CPUS:-4-11}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
REPLAY_RATE=${BENCH_REPLAY_RATE:-0}
# Hold-time both session ends propose (negotiated = min). 90 for
# everyone: F7 (the select! read-drop) is FIXED as of 47ef0ee — the
# post-fix full-table re-run went unpaced at hold 90 with zero
# malformed. The pre-fix mitigation was BENCH_HOLD=900 + pacing
# 120 msg/s (kept here as history; do not re-enable without cause).
HOLD=${BENCH_HOLD:-90}
TIMEOUT=${BENCH_TIMEOUT:-3600}
# P0-b harness fix (2026-10-16): the SUT containers get a large
# netlink receive buffer. Diagnosis of the 2026-10-15/16 post-F8
# poll loss: rousterd's netlink socket is subscribed to the route
# multicast groups, so every install of the 1.1M-route storm echoes
# a notification back to the same socket; when the daemon's single
# netlink connection task is starved >~25 ms under the storm, the
# default rcvbuf (net.core.rmem_default = 212992) overruns (ENOBUFS)
# and the kernel DROPS datagrams — including ACKs for in-flight
# installs. netlink-proto 0.12.2 request futures have no timeout:
# each dropped ACK hangs its route_replace future, the zapi drain
# arm of rousterd's main loop never returns, the reconcile tick
# stops, and the status file freezes (the "lost poll side"). The
# rig-side fix gives the socket ~2 s of starvation slack instead of
# ~25 ms; applied symmetrically to BOTH SUT starters (§F). The
# SUT-side hardening (ACK timeout / overrun resync) is escalated as
# a finding for the owner. BENCH_SUT_RMEM=0 disables for A/B runs.
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
OUT_DIR="target/bench-logs/$MODE-$TS"
mkdir -p "$OUT_DIR"
echo "bench-e1-ingest: mode=$MODE feed=$FEED_MRT limit=$FEED_LIMIT (target $FEED_COUNT) runs=$RUNS"
echo "  sut cpus=$SUT_CPUS  injector cpus=$INJ_CPUS  rate=$REPLAY_RATE  out=$OUT_DIR"

# --- images -----------------------------------------------------------
# Network first, then the probe on it: some hosts run a daemon whose
# default docker0 bridge is absent, while daemon-created custom
# bridges work fine (bench boxes); the probe must exercise the network
# the runs will actually use.
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
perl -e 'alarm 15; exec @ARGV' docker run --rm --network "$NET_NAME" --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
# Any leftover bench container would hold the fixed IPs (a killed
# harness run leaves no trap behind).
docker rm -f $(docker ps -aq --filter name=b1-) >/dev/null 2>&1 || true

# --- binaries (rouster modes need the musl build) ----------------------

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
        --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    for b in rousterd rousterctl; do
        docker cp "$BIN_DIR/$b" "$1:/usr/local/bin/$b"
    done
    docker cp "$BIN_DIR/bgpd" "$1:/usr/local/bin/rouster-bgpd"
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
        --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
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

start_sut_hybrid() { # name — config B: FRR 10.2.2 bgpd+mgmtd on the ROUSTER core
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" $SUT_SYSCTLS \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    for b in rousterd rousterctl; do
        docker cp "$BIN_DIR/$b" "$1:/usr/local/bin/$b"
    done
    docker exec "$1" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
    # rousterd's zapi socket at the FRR-conventional path (the z5b
    # recipe: unmodified daemons find their socket where they expect).
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /var/run/frr/zserv.api' > /etc/rouster.conf"
    docker exec -d "$1" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
    wait_up "$1" "rousterd zapi listening" 30 "grep -q 'zapi: listening' /var/log/rousterd.log"
    wait_up "$1" "zapi socket" 10 "test -S /var/run/frr/zserv.api"
    docker exec "$1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/tmp/mgmtd.log --log-level info"
    wait_up "$1" "frr mgmtd vty" 30 "test -S /var/run/frr/mgmtd.vty"
    docker exec "$1" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:/tmp/bgpd.log --log-level info"
    wait_up "$1" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
    docker exec "$1" sh -c "printf '%s\n' \
        'frr version 10.2' \
        'frr defaults traditional' \
        'hostname bench-hybrid' \
        'router bgp $SUT_AS' \
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
    docker cp "$BIN_DIR/mrt-replay" "$1:/usr/local/bin/mrt-replay"
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

    case "$MODE" in
        frr)    start_sut_frr "$SUT" ;;
        hybrid) start_sut_hybrid "$SUT" ;;
        *)      start_sut_rouster "$SUT" ;;
    esac
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

    if [ "$MODE" = frr ] || [ "$MODE" = hybrid ]; then
        docker exec "$SUT" sh -c "vtysh -c 'show bgp neighbor $INJ_IP'" | head -20 > "$RUN_DIR/pre-run-neighbor.txt" || true
    fi

    echo "    launching poller + injector"
    python3 scripts/bench-poll.py \
        --sut-container "$SUT" --inj-container "$INJ" \
        --mode "$(if [ "$MODE" = frr ]; then echo frr; elif [ "$MODE" = hybrid ]; then echo hybrid; else echo rouster; fi)" \
        --target-count "$FEED_COUNT" --timeout "$TIMEOUT" \
        $( [ "$MODE" = hybrid ] && echo "--bgpd-log /tmp/bgpd.log" ) \
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
    elif [ "$MODE" = hybrid ]; then
        for f in bgpd mgmtd; do
            docker cp "$SUT:/tmp/$f.log" "$RUN_DIR/$f.log" 2>/dev/null || true
        done
        docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
        docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary'; ip route show proto bgp | wc -l" > "$RUN_DIR/final-vtysh.txt" 2>&1 || true
        docker exec "$SUT" sh -c "cat /proc/\$(pidof bgpd | awk '{print \$1}')/stat /proc/\$(pidof rousterd | awk '{print \$1}')/stat" > "$RUN_DIR/final-proc-stat.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "cat /proc/\$(pidof bgpd)/status /proc/\$(pidof rousterd)/status" > "$RUN_DIR/final-proc-status.txt" 2>/dev/null || true
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
SUMM_MODE=rouster; [ "$MODE" = frr ] && SUMM_MODE=frr
python3 scripts/bench-summarize.py --out-dir "$OUT_DIR" --mode "$SUMM_MODE" --target-count "$FEED_COUNT" --clk-tck "$CLK" || true
echo "bench-e1-ingest: done — $OUT_DIR/summary.json"
