#!/usr/bin/env bash
# bench-x.sh — the rewrite's remaining experiment cells on one harness:
#   e1diff    E1: full-table installed-state diff oracle (A vs D):
#             kernel proto-bgp (prefix, nexthop) sets, sorted, diffed.
#   e4conv    E4: link failure and restoration — the SUT's only transit
#             interface flapped down/up; the BGP session survives (hold
#             90); measure kernel-count collapse/restore + probe loss.
#   e5recover E5: speaker crash+restart (replay recovery, stale window)
#             and core crash+restart, both systems.
#   e6mixed   E6: mixed composition — FRR staticd + rouster bgpd on the
#             rousterd core; static churn under a loaded BGP table.
#   e7overload E7: sustained 50% flap storm + backlog drain.
# Rig: the frozen bench-net shape (BENCH_* env), DGX-safe (probe on the
# run network, BENCH_BIN_DIR prebuilts, rmem default).
#
#   scripts/bench-x.sh <cell> <feed-mrt> [announce-file]
set -euo pipefail
cd "$(dirname "$0")/.."

CELL=${1:?usage: bench-x.sh e1diff|e4conv|e5recover|e6mixed|e7overload <raw-mrt> [announce]}
FEED_MRT=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
ANNOUNCE=${3:-}
IMAGE=frr-testbed:10.2.2
SUT_AS=65000; INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
SUT_CPUS=${BENCH_SUT_CPUS:-5-9}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
HOLD=${BENCH_HOLD:-90}
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/x-$CELL-$TS"
mkdir -p "$OUT_DIR"
echo "bench-x: cell=$CELL feed=$FEED_MRT out=$OUT_DIR"

BIN_DIR=${BENCH_BIN_DIR:-target/aarch64-unknown-linux-musl/release}
FRRLOG=/tmp/frrrun

docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
perl -e 'alarm 15; exec @ARGV' docker run --rm --network "$NET_NAME" --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
for pfx in x1 x4 x5 x6 x7; do
    docker rm -f $(docker ps -aq --filter name="$pfx-") >/dev/null 2>&1 || true
done

wait_up() { docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
    for _ in $(seq 1 "$3"); do docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0; sleep 1; done
    echo "FAIL: $2 (waited ${3}s)" >&2; return 1; }

new_sut() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$1" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
}

start_rousterd() { # name
    docker cp "$BIN_DIR/rousterd" "$1:/usr/local/bin/rousterd"
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /var/run/frr/zserv.api' > /etc/rouster.conf"
    docker exec -d "$1" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
    wait_up "$1" "rousterd zapi listening" 30 "grep -q 'zapi: listening' /var/log/rousterd.log"
}

start_rouster_bgpd() { # name
    docker cp "$BIN_DIR/bgpd" "$1:/usr/local/bin/rouster-bgpd"
    docker exec "$1" sh -c "printf '%s\n' \
        'zapi socket /var/run/frr/zserv.api' \
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

start_frr_daemons() { # name  (zebra + mgmtd + bgpd)
    docker exec "$1" sh -c "/usr/lib/frr/zebra -d -z /var/run/frr/zserv.api --log file:$FRRLOG/zebra.log --log-level info"
    wait_up "$1" "frr zebra vty" 30 "test -S /var/run/frr/zebra.vty"
    docker exec "$1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/mgmtd.log --log-level info"
    wait_up "$1" "frr mgmtd vty" 30 "test -S /var/run/frr/mgmtd.vty"
    docker exec "$1" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
    wait_up "$1" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
    docker exec "$1" sh -c "printf '%s\n' \
        'frr version 10.2' \
        'frr defaults traditional' \
        'hostname bench-x' \
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
        docker exec "$1" vtysh -b >/dev/null 2>&1 || true; sleep 2
        docker exec "$1" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP" && break
    done
    wait_up "$1" "frr bgpd bound :179" 30 "grep -qi '00B3' /proc/net/tcp"
}

start_staticd() { # name  (FRR staticd on the rouster core)
    docker exec "$1" sh -c "/usr/lib/frr/staticd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/staticd.log --log-level info"
    wait_up "$1" "frr staticd vty" 30 "test -S /var/run/frr/staticd.vty"
}

start_injector() { # name  (mrt-replay)
    docker run -d --name "$1" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" \
        -v "$FEED_MRT":/feed.mrt:ro \
        --entrypoint sleep alpine:3.20 infinity >/dev/null
    docker cp "$BIN_DIR/mrt-replay" "$1:/usr/local/bin/mrt-replay"
}

INJ_ARGS_FOR() { # limit
    echo "--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
        --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
        --prepend-as $INJ_AS --next-hop $INJ_IP --limit $1 \
        --rate 0 --hold $HOLD"
}

kern_count() { docker exec "$1" sh -c "ip route show proto 186 2>/dev/null | grep -c ." || echo 0; }
kern_dump()  { docker exec "$1" sh -c "ip route show proto 186 2>/dev/null" \
    | awk '{nh="-"; for(i=2;i<=NF;i++){if($i=="via")nh=$(i+1)}; print $1, nh}' | sort; }
# The timeline runs INSIDE the SUT as a detached process: host-side
# concurrent docker-exec streams stalled the harness on the bench box
# (both loops froze in pipe_read); one in-container loop, copied out
# at capture, has no host-side contention at all.
timeline() { # sut name interval — starts the in-SUT counter
    docker exec -d "$1" sh -c '
        : > /tl-'"$2"'.csv
        end=$(( $(date +%s) + 1800 ))
        while :; do
            echo "$(date +%s.%N) $(ip route show proto 186 2>/dev/null | grep -c .)" >> /tl-'"$2"'.csv
            [ "$(date +%s)" -gt "$end" ] && break
            sleep '"$3"'
        done'
}
timeline_stop() { # sut name out.csv
    docker exec "$1" sh -c "pkill -f tl- 2>/dev/null" >/dev/null 2>&1 || true
    sleep 1
    docker cp "$1:/tl-$2.csv" "$3" 2>/dev/null || true
}
note() { echo "X-NOTE $*" | tee -a "$OUT_DIR/notes.txt"; }
pass() { echo "X-PASS $*" | tee -a "$OUT_DIR/notes.txt"; }
fail() { echo "X-FAIL $*" | tee -a "$OUT_DIR/notes.txt"; }

# =====================================================================
case "$CELL" in
e1diff)
    LIMIT=${BENCH_X_LIMIT:-100000}
    NEED=$((LIMIT > 2000 ? LIMIT - LIMIT/200 : LIMIT - 2))
    for SIDE in frr rouster; do
        SUT=x1-sut-$TS-$SIDE; INJ=x1-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e1diff side=$SIDE limit=$LIMIT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        start_injector "$INJ"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
        for _ in $(seq 1 300); do
            c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
        done
        sleep 5
        kern_dump "$SUT" > "$OUT_DIR/kernel-$SIDE.txt"
        note "side=$SIDE final-kernel=$(wc -l < "$OUT_DIR/kernel-$SIDE.txt")"
        docker cp "$INJ:/var/log/replay.txt" "$OUT_DIR/replay-$SIDE.txt" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    A=$(wc -l < "$OUT_DIR/kernel-frr.txt"); D=$(wc -l < "$OUT_DIR/kernel-rouster.txt")
    ONLY_A=$(comm -23 "$OUT_DIR/kernel-frr.txt" "$OUT_DIR/kernel-rouster.txt" | wc -l)
    ONLY_D=$(comm -13 "$OUT_DIR/kernel-frr.txt" "$OUT_DIR/kernel-rouster.txt" | wc -l)
    note "e1diff result: A=$A D=$D onlyA=$ONLY_A onlyD=$ONLY_D"
    comm -23 "$OUT_DIR/kernel-frr.txt" "$OUT_DIR/kernel-rouster.txt" | head -5 >> "$OUT_DIR/notes.txt" || true
    comm -13 "$OUT_DIR/kernel-frr.txt" "$OUT_DIR/kernel-rouster.txt" | head -5 >> "$OUT_DIR/notes.txt" || true
    if [ "$ONLY_A" = 0 ] && [ "$ONLY_D" = 0 ]; then
        pass "e1diff: installed (prefix,nexthop) sets identical ($A entries)"
    else
        fail "e1diff: sets differ (onlyA=$ONLY_A onlyD=$ONLY_D)"
    fi
    ;;
e4conv)
    LIMIT=${BENCH_X_LIMIT:-10000}
    NEED=$((LIMIT - 20))
    for SIDE in frr rouster; do
        SUT=x4-sut-$TS-$SIDE; INJ=x4-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e4conv side=$SIDE limit=$LIMIT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        start_injector "$INJ"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
        for _ in $(seq 1 120); do
            c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
        done
        sleep 3
        timeline "$SUT" "$SIDE" 0.3
        note "side=$SIDE steady-kernel=$(kern_count "$SUT") — flapping eth0 down"
        T0=$(date +%s.%N)
        docker exec "$SUT" ip link set eth0 down
        sleep 4
        T1=$(date +%s.%N)
        docker exec "$SUT" ip link set eth0 up
        note "side=$SIDE link back up; watching restore"
        for _ in $(seq 1 240); do
            c=$(kern_count "$SUT"; ); [ "${c:-0}" -ge "$NEED" ] 2>/dev/null && break; sleep 0.5
        done
        T2=$(date +%s.%N)
        TL=$OUT_DIR/timeline-$SIDE.csv
        timeline_stop "$SUT" "$SIDE" "$TL"
        python3 - "$T0" "$T1" "$T2" "$TL" >> "$OUT_DIR/notes.txt" <<'PYEOF'
import sys
t0, t1, t2, tl = sys.argv[1:5]
t0, t1, t2 = float(t0), float(t1), float(t2)
rows = [l.split() for l in open(tl) if l.strip()]
kc = [(float(t), int(n)) for t, n in rows]
def at_window(a, b):
    sel = [(t, n) for t, n in kc if a <= t <= b]
    return sel
pre  = at_window(t0 - 3, t0)
down = at_window(t1, t2)
post = at_window(t2, t2 + 60)
mn_down = min((n for _, n in down), default=None)
t_restore = next((t - t1 for t, n in kc if t > t1 and n >= (max(n for _, n in pre) if pre else 0) - 20), None)
print(f"X-NOTE e4conv timeline: pre={max((n for _, n in pre), default=0)} "
      f"min_during_outage={mn_down} restore_after_up_s={t_restore:.1f}" if t_restore else
      f"X-NOTE e4conv timeline: pre={max((n for _, n in pre), default=0)} min_during_outage={mn_down} NOT-RESTORED")
PYEOF
        docker cp "$INJ:/var/log/replay.txt" "$OUT_DIR/replay-$SIDE.txt" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;
e5recover)
    LIMIT=${BENCH_X_LIMIT:-100000}
    NEED=$((LIMIT > 2000 ? LIMIT - LIMIT/200 : LIMIT - 2))
    for SIDE in frr rouster; do
      for SCN in speaker core; do
        SUT=x5-sut-$TS-$SIDE-$SCN; INJ=x5-inj-$TS-$SIDE-$SCN
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e5recover side=$SIDE scenario=$SCN limit=$LIMIT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        start_injector "$INJ"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
        for _ in $(seq 1 300); do
            c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
        done
        sleep 3
        timeline "$SUT" "$SIDE-$SCN" 1
        TKILL=$(date +%s.%N)
        if [ "$SCN" = speaker ]; then
            docker exec "$SUT" sh -c "kill -9 \$(pidof bgpd rouster-bgpd 2>/dev/null | awk '{print \$NF}') 2>/dev/null || kill -9 \$(pidof bgpd)"
        else
            if [ "$SIDE" = frr ]; then docker exec "$SUT" sh -c "kill -9 \$(pidof zebra)"
            else docker exec "$SUT" sh -c "kill -9 \$(pidof rousterd) \$(pidof rouster-bgpd)"; fi
        fi
        sleep 5
        TRESTART=$(date +%s.%N)
        if [ "$SCN" = speaker ]; then
            if [ "$SIDE" = frr ]; then
                docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
            else
                docker exec -d "$SUT" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
            fi
        else
            if [ "$SIDE" = frr ]; then
                docker exec "$SUT" sh -c "/usr/lib/frr/zebra -d -z /var/run/frr/zserv.api --log file:$FRRLOG/zebra.log --log-level info"
            else
                docker exec -d "$SUT" sh -c "rousterd --config /etc/rouster.conf > /var/log/rousterd.log 2>&1"
                sleep 3
                docker exec -d "$SUT" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
            fi
        fi
        # re-announce: restart the injector so the table is replayed
        docker rm -f "$INJ" >/dev/null 2>&1 || true
        INJ=x5-inj2-$TS-$SIDE-$SCN
        start_injector "$INJ"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
        for _ in $(seq 1 300); do
            c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
        done
        TFULL=$(date +%s.%N)
        TL=$OUT_DIR/tl-$SIDE-$SCN.csv
        timeline_stop "$SUT" "$SIDE-$SCN" "$TL"
        python3 - "$TKILL" "$TRESTART" "$TFULL" "$TL" >> "$OUT_DIR/notes.txt" <<'PYEOF'
import sys
tk, tr, tf, tl = (float(x) for x in sys.argv[1:5])
kc = [(float(t), int(n)) for t, n in (l.split() for l in open(tl) if l.strip())]
during = [n for t, n in kc if tk <= t <= tr + 2]
after_kill = [n for t, n in kc if tk <= t <= tf]
print(f"X-NOTE e5recover timeline: kill_to_restart_s={tr-tk:.1f} "
      f"restart_to_full_s={tf-tr:.1f} total_outage_s={tf-tk:.1f} "
      f"min_kernel_in_first_window={min(during) if during else 'n/a'} "
      f"max_kernel_after_kill={max(after_kill) if after_kill else 0}")
PYEOF
        docker cp "$INJ:/var/log/replay.txt" "$OUT_DIR/replay-$SIDE-$SCN.txt" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
      done
    done
    ;;
e6mixed)
    LIMIT=${BENCH_X_LIMIT:-100000}
    NEED=$((LIMIT > 2000 ? LIMIT - LIMIT/200 : LIMIT - 2))
    SUT=x6-sut-$TS; INJ=x6-inj-$TS
    trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
    note "=== e6mixed limit=$LIMIT (FRR staticd + rouster bgpd on rousterd)"
    new_sut "$SUT"
    start_rousterd "$SUT"
    start_rouster_bgpd "$SUT"
    start_staticd "$SUT"
    docker exec "$SUT" sh -c "printf '%s\n' \
        'frr version 10.2' \
        'frr defaults traditional' \
        'hostname bench-x6' \
        'ip route 198.51.100.0/24 172.31.255.10' \
        'ip route 198.51.200.0/24 172.31.255.10' \
        'ip route 203.0.113.0/25 172.31.255.10' \
        > /etc/frr/frr.conf"
    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
    sleep 3
    S_COUNT=$(docker exec "$SUT" sh -c "ip route show proto static | grep -c ." || echo 0)
    note "static routes installed: $S_COUNT (expect 3)"
    start_injector "$INJ"
    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
    for _ in $(seq 1 300); do
        c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
    done
    BGP_FULL=$(kern_count "$SUT")
    S_AFTER=$(docker exec "$SUT" sh -c "ip route show proto static | grep -c ." || echo 0)
    note "bgp kernel count under static coexistence: $BGP_FULL; static still: $S_AFTER"
    # static churn under the loaded table: withdraw + re-add via config swap
    T0=$(date +%s.%N)
    docker exec "$SUT" sh -c "printf '%s\n' \
        'frr version 10.2' 'frr defaults traditional' 'hostname bench-x6' \
        'ip route 198.51.100.0/24 172.31.255.10' \
        > /etc/frr/frr.conf"
    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
    sleep 3
    S_MID=$(docker exec "$SUT" sh -c "ip route show proto static | grep -c ." || echo 0)
    BGP_MID=$(kern_count "$SUT")
    docker exec "$SUT" sh -c "printf '%s\n' \
        'frr version 10.2' 'frr defaults traditional' 'hostname bench-x6' \
        'ip route 198.51.100.0/24 172.31.255.10' \
        'ip route 198.51.200.0/24 172.31.255.10' \
        'ip route 203.0.113.0/25 172.31.255.10' \
        > /etc/frr/frr.conf"
    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
    sleep 3
    S_END=$(docker exec "$SUT" sh -c "ip route show proto static | grep -c ." || echo 0)
    BGP_END=$(kern_count "$SUT")
    T1=$(date +%s.%N)
    note "churn: static $S_COUNT->$S_MID->$S_END (expect 3->1->3); bgp $BGP_FULL->$BGP_MID->$BGP_END; churn_wall_s=$(python3 -c "print(f'{$T1-$T0:.1f}')")"
    if [ "$S_COUNT" = 3 ] && [ "$S_MID" = 1 ] && [ "$S_END" = 3 ] \
       && [ "$BGP_FULL" -ge "$NEED" ] && [ "$BGP_MID" -ge "$NEED" ] && [ "$BGP_END" -ge "$NEED" ]; then
        pass "e6mixed: static churn exact under a full BGP table; bgp count stable"
    else
        fail "e6mixed: see counts above"
    fi
    docker cp "$INJ:/var/log/replay.txt" "$OUT_DIR/replay.txt" 2>/dev/null || true
    docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
    ;;
e7overload)
    LIMIT=${BENCH_X_LIMIT:-100000}
    ROUNDS=${BENCH_X_ROUNDS:-30}
    [ -n "$ANNOUNCE" ] || { echo "e7overload needs the announce file" >&2; exit 1; }
    ANN_CP=$(cd "$(dirname "$ANNOUNCE")" && pwd)/$(basename "$ANNOUNCE")
    for SIDE in frr rouster; do
        SUT=x7-sut-$TS-$SIDE; INJ=x7-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e7overload side=$SIDE rounds=$ROUNDS (50% flaps)"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" \
            -v "$ANN_CP":/feed.announce:ro \
            --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null 2>&1 \
            || docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" -v "$ANN_CP":/feed.announce:ro \
            --entrypoint sleep bench-exabgp:local infinity
        docker cp scripts/bench-flap.py "$INJ:/bench-flap.py"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        timeline "$SUT" "$SIDE" 1
        T0=$(date +%s.%N)
        docker exec "$INJ" sh -c "python3 /bench-flap.py --peer $SUT_IP:179 \
            --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
            --announce /feed.announce --limit $LIMIT --flap-every 2 \
            --rounds $ROUNDS --hold $HOLD --steady-wait 8 --round-gap 0.5 \
            --linger 10" > "$OUT_DIR/flap-$SIDE.txt" 2>&1
        T1=$(date +%s.%N)
        # drain: wait for the count to stabilize at full
        for _ in $(seq 1 180); do
            c1=$(kern_count "$SUT"); sleep 2; c2=$(kern_count "$SUT")
            [ "$c1" = "$c2" ] && [ "$c1" -ge $((LIMIT - 20)) ] 2>/dev/null && break
        done
        T2=$(date +%s.%N)
        TL=$OUT_DIR/tl-$SIDE.csv
        timeline_stop "$SUT" "$SIDE" "$TL"
        RSS=$(docker exec "$SUT" sh -c "awk '/VmRSS/{print \$2}' /proc/\$(pidof zebra rousterd | awk '{print \$1}')/status" 2>/dev/null || echo "?")
        note "side=$SIDE storm_wall_s=$(python3 -c "print(f'{$T1-$T0:.1f}')") drain_s=$(python3 -c "print(f'{$T2-$T1:.1f}')") final=$(kern_count "$SUT") core_rss_kb=$RSS"
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;
*) echo "unknown cell $CELL" >&2; exit 1 ;;
esac
echo "bench-x: done — $OUT_DIR"
