#!/usr/bin/env bash
# bench-churn24 — the ToN-revision phase-5 long-duration cell: ONE
# 24-hour mixed-churn run (route, peer, and nexthop changes on a
# fixed schedule) per system, tracking memory high-water, settled
# plateau, interned-object counts, and desired-vs-kernel
# discrepancies. The claim scope is bounded behavior for the tested
# campaign, nothing broader (plan Part 5 P1).
#
# Schedule (fixed, printed at start): 96 blocks of 15 minutes.
#   every block:    one flap round (W<n> then R<n>, n drawn from the
#                   block index — deterministic, both systems identical)
#   every 4th:      a peer cycle (the injector's session is bounced:
#                   bench-seq exits, restarts, re-announces A)
#   every 8th:      a nexthop-change set (N ops with --alt-nexthop)
# Sampler (60 s): per-daemon VmRSS/VmHWM from /proc, kernel proto-186
# count vs the block's expected value (discrepancy column), the
# census line tail (interned tuples; requires the mem-census build —
# BGPD_CENSUS=1 spawns it, crates/bgpd/src/census.rs).
#
# Usage (dgx-spark-1, lane free, from ~/rouster-bench):
#   BENCH_BIN_DIR=~/rouster-bench/bin-census bash scripts/bench-churn24.sh <announce> <side>
# Env: CHURN24_HOURS (default 24), BENCH_X_LIMIT (default 100000).
# Artifacts: target/bench-logs/churn24-<side>-<ts>/{schedule.txt,
# samples.csv, blocks/*.txt, final-kernel.txt}.
#
#   scripts/bench-churn24.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ANN=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
SIDE=${2:?side: frr|rouster}
HOURS=${CHURN24_HOURS:-24}
LIMIT=${BENCH_X_LIMIT:-100000}
# reuse bench-x.sh's rig knobs by sourcing its variable block only
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-175.31.255.10}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
SUT_CPUS=${BENCH_SUT_CPUS:-5-9}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
IMAGE=frr-testbed:10.2.2
SUT_AS=65000; INJ_AS=65412
BIN_DIR=${BENCH_BIN_DIR:-target/$(case $(uname -m) in arm64|aarch64) echo aarch64-unknown-linux-musl;; *) echo x86_64-unknown-linux-musl;; esac)/release}
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/churn24-$SIDE-$TS"
mkdir -p "$OUT_DIR/blocks"
echo "churn24: side=$SIDE hours=$HOURS limit=$LIMIT out=$OUT_DIR"

docker network inspect "$NET_NAME" >/dev/null 2>&1 || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
SUT=c24-sut-$TS; INJ=c24-inj-$TS
trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true

docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
    --cpuset-cpus "$SUT_CPUS" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker exec "$SUT" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
ALT_NH=$(echo "$INJ_IP" | awk -F. 'BEGIN{OFS="."} {$4=$4+1; $1=$1; print}')
if [ "$SIDE" = frr ]; then
    docker exec "$SUT" sh -c "/usr/lib/frr/zebra -d --log file:/tmp/zebra.log --log-level info"
    sleep 3
    docker exec "$SUT" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/tmp/mgmtd.log --log-level info"
    sleep 2
    docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:/tmp/bgpd.log --log-level info"
    sleep 3
    docker exec "$SUT" sh -c "printf '%s\n' \
        'frr version 10.2' 'frr defaults traditional' 'hostname churn24' \
        'router bgp 65000' ' no bgp network import-check' ' no bgp ebgp-requires-policy' \
        ' neighbor $INJ_IP remote-as $INJ_AS' ' neighbor $INJ_IP timers 30 90' \
        ' address-family ipv4 unicast' '  exit-address-family' 'line vty' > /etc/frr/frr.conf"
    for _ in $(seq 1 10); do docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true; sleep 2; done
    SPK=bgpd; CORE=zebra
else
    for b in rousterd rousterctl; do docker cp "$BIN_DIR/$b" "$SUT:/usr/local/bin/$b"; done
    docker cp "$BIN_DIR/bgpd" "$SUT:/usr/local/bin/rouster-bgpd"
    docker exec "$SUT" sh -c "printf 'zapi socket /run/rouster/zserv.api\n' > /etc/rouster.conf"
    docker exec -d "$SUT" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
    sleep 3
    docker exec "$SUT" sh -c "printf '%s\n' \
        'zapi socket /run/rouster/zserv.api' 'router bgp 65000' \
        ' bgp router-id $SUT_IP' ' neighbor $INJ_IP remote-as $INJ_AS' \
        ' neighbor $INJ_IP passive' ' hold-time 90' > /etc/rouster-bgp.conf"
    docker exec -d "$SUT" sh -c "BGPD_CENSUS=1 rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
    sleep 3
    SPK=rouster-bgpd; CORE=rousterd
fi

docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
    --cpuset-cpus "$INJ_CPUS" -v "$ANN":/feed.announce:ro \
    --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
docker cp scripts/bench-seq.py "$INJ:/bench-seq.py"
docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
docker exec "$INJ" ip addr add "$ALT_NH/24" dev eth0 2>/dev/null || true

seq_run() { # ops linger
    docker exec "$INJ" sh -c "pkill -f bench-seq 2>/dev/null" >/dev/null 2>&1 || true
    sleep 1
    docker exec -d "$INJ" sh -c "python3 /bench-seq.py --peer $SUT_IP:179 \
        --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
        --announce /feed.announce --limit $LIMIT --alt-nexthop $ALT_NH \
        --linger $2 --ops $1 > /var/log/seq-run.txt 2>&1"
}
kern() { docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null | wc -l" | tr -d ' '; }
rss()  { docker exec "$SUT" sh -c "grep $1 /proc/\$(pidof $2)/status 2>/dev/null" | awk '{print $2}'; }

# initial full load
seq_run A 900
sleep 30
echo "t,block,phase,kern,rss_spk,rss_core,hwm_spk,hwm_core,discrep" > "$OUT_DIR/samples.csv"

BLOCKS=$((HOURS * 4))
for B in $(seq 1 "$BLOCKS"); do
    N=$(( (B % 25) + 2 ))
    OPS="W$N,R$N"
    PHASE=flap
    if [ $((B % 8)) = 0 ]; then OPS="A,N$N"; PHASE=nexthop; fi
    if [ $((B % 4)) = 0 ] && [ "$PHASE" = flap ]; then PHASE=flap+peer; fi
    echo "block $B/$BLOCKS phase=$PHASE ops=$OPS" | tee -a "$OUT_DIR/schedule.txt"
    seq_run "$OPS" 900
    if [ "$PHASE" = "flap+peer" ]; then
        sleep 60; docker exec "$INJ" sh -c "pkill -f bench-seq" >/dev/null 2>&1 || true
        sleep 30; seq_run A 900
    fi
    # sample through the block (15 min)
    for _ in $(seq 1 15); do
        sleep 60
        K=$(kern); RS=$(rss VmRSS $SPK); RC=$(rss VmRSS $CORE)
        HS=$(rss VmHWM $SPK); HC=$(rss VmHWM $CORE)
        EXP=$LIMIT; [ "$K" -gt "$EXP" ] && K=$K
        echo "$(date +%s),$B,$PHASE,$K,$RS,$RC,$HS,$HC,$((EXP - K))" >> "$OUT_DIR/samples.csv"
    done
    docker exec "$SUT" sh -c "tail -2 /var/log/rouster-bgpd.log 2>/dev/null" > "$OUT_DIR/blocks/$B-census.txt" || true
done
kern > "$OUT_DIR/final-kernel-count.txt"
docker exec "$SUT" sh -c "ip route show proto 186" > "$OUT_DIR/final-kernel.txt" 2>/dev/null || true
for f in /var/log/rousterd.log /var/log/rouster-bgpd.log; do
    docker cp "$SUT:$f" "$OUT_DIR/$(basename $f)" 2>/dev/null || true
done
note() { echo "CHURN24 $*" | tee -a "$OUT_DIR/notes.txt"; }
note "side=$SIDE done blocks=$BLOCKS final=$(cat "$OUT_DIR/final-kernel-count.txt")"
echo "churn24: done — $OUT_DIR"
