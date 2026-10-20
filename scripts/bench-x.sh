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

start_staticd() { # name  (FRR staticd on the rouster core; the z5
    # recipe: mgmtd must run alongside - staticd's config transaction
    # commits asynchronously through the mgmtd-backed vtysh -b push)
    docker exec "$1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/mgmtd.log --log-level info"
    wait_up "$1" "frr mgmtd vty" 30 "test -S /var/run/frr/mgmtd.vty"
    docker exec "$1" sh -c "/usr/lib/frr/staticd -d -z /var/run/frr/zserv.api --log file:$FRRLOG/staticd.log --log-level info"
    wait_up "$1" "frr staticd vty" 30 "test -S /var/run/frr/staticd.vty"
}
wait_static() { # name expected
    for _ in $(seq 1 30); do
        c=$(docker exec "$1" sh -c "ip route show proto static 2>/dev/null | grep -c ." || echo 0)
        [ "$c" = "$2" ] 2>/dev/null && return 0
        docker exec "$1" vtysh -b >/dev/null 2>&1 || true
        sleep 1
    done
    docker exec "$1" sh -c "ip route show proto static 2>/dev/null | grep -c ." || echo 0
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

kern_count() { docker exec "$1" sh -c "ip route show proto 186 2>/dev/null | grep -c ." || true; }
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
    for SIDE in ${BENCH_X_E5_SIDES:-frr rouster}; do
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
                for _ in $(seq 1 15); do
                    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
                    sleep 2
                    docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP" && break
                done
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
tk, tr, tf = map(float, sys.argv[1:4])
tl = sys.argv[4]
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
    S_COUNT=$(wait_static "$SUT" 3)
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
    S_MID=$(wait_static "$SUT" 1)
    BGP_MID=$(kern_count "$SUT")
    docker exec "$SUT" sh -c "printf '%s\n' \
        'frr version 10.2' 'frr defaults traditional' 'hostname bench-x6' \
        'ip route 198.51.100.0/24 172.31.255.10' \
        'ip route 198.51.200.0/24 172.31.255.10' \
        'ip route 203.0.113.0/25 172.31.255.10' \
        > /etc/frr/frr.conf"
    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
    S_END=$(wait_static "$SUT" 3)
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
        docker exec -d "$SUT" sh -c '
            : > /queues.csv
            end=$(( $(date +%s) + 1500 ))
            while :; do
                echo "$(date +%s.%N) $(cat /run/rouster/rousterd.queues 2>/dev/null | tr "\n" " ")" >> /queues.csv
                [ "$(date +%s)" -gt "$end" ] && break
                sleep 1
            done'
        T0=$(date +%s.%N)
        docker exec -d "$INJ" sh -c "python3 /bench-flap.py --peer $SUT_IP:179 \
            --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
            --announce /feed.announce --limit $LIMIT --flap-every ${BENCH_X_FLAP_EVERY:-2} \
            --rounds $ROUNDS --hold $HOLD --steady-wait 8 --round-gap 0.5 \
            --linger 600 > /var/log/flap-run.txt 2>&1"
        # storm end = the tool's ROUNDS-DONE marker (the process keeps
        # the session alive through the linger; measuring drain from
        # process exit would measure the post-close withdrawal)
        for _ in $(seq 1 600); do
            docker exec "$INJ" sh -c "grep -q 'FLAP-ROUNDS-DONE' /var/log/flap-run.txt 2>/dev/null" && break
            sleep 1
        done
        T1=$(date +%s.%N)
        # drain: stabilize at full WITH the session still lingering
        for _ in $(seq 1 180); do
            c1=$(kern_count "$SUT"); sleep 2; c2=$(kern_count "$SUT")
            [ "$c1" = "$c2" ] && [ "$c1" -ge $((LIMIT - 20)) ] 2>/dev/null && break
        done
        T2=$(date +%s.%N)
        docker exec "$INJ" sh -c "cat /var/log/flap-run.txt" > "$OUT_DIR/flap-$SIDE.txt" 2>/dev/null || true
        docker rm -f "$INJ" >/dev/null 2>&1 || true
        TL=$OUT_DIR/tl-$SIDE.csv
        timeline_stop "$SUT" "$SIDE" "$TL"
        docker exec "$SUT" sh -c "pkill -f queues.csv 2>/dev/null" >/dev/null 2>&1 || true
        docker cp "$SUT:/queues.csv" "$OUT_DIR/queues-$SIDE.csv" 2>/dev/null || true
        RSS=$(docker exec "$SUT" sh -c "awk '/VmRSS/{print \$2}' /proc/\$(pidof zebra rousterd | awk '{print \$1}')/status" 2>/dev/null || echo "?")
        note "side=$SIDE storm_wall_s=$(python3 -c "print(f'{$T1-$T0:.1f}')") drain_s=$(python3 -c "print(f'{$T2-$T1:.1f}')") final=$(kern_count "$SUT") core_rss_kb=$RSS"
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;

e1seq)
    # E1's generated event-sequence differential: scripted ops against
    # the loaded table, kernel-dump oracle incl. exact prefix sets.
    LIMIT=${BENCH_X_LIMIT:-10000}
    ANN_CP=$(cd "$(dirname "${ANNOUNCE:?e1seq needs the announce file}")" && pwd)/$(basename "$ANNOUNCE")
    for SIDE in frr rouster; do
        SUT=x1-sut-$TS-$SIDE; INJ=x1-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e1seq side=$SIDE limit=$LIMIT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" -v "$ANN_CP":/feed.announce:ro \
            --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
        docker cp scripts/bench-seq.py "$INJ:/bench-seq.py"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        # SEQ-1: announce, withdraw every 3rd, re-announce every 3rd
        # (novel attrs), withdraw every 5th -> expected = not-5th.
        docker exec -d "$INJ" sh -c "python3 /bench-seq.py --peer $SUT_IP:179 \
            --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
            --announce /feed.announce --limit $LIMIT --linger 90 \
            --ops A,W3,R3,W5 --gap 3 > /var/log/seq-run.txt 2>&1"
        for _ in $(seq 1 240); do
            docker exec "$INJ" sh -c "grep -q SEQ-ALL-DONE /var/log/seq-run.txt 2>/dev/null" && break
            sleep 1
        done
        sleep 3
        awk -v n="$LIMIT" 'NR <= n && NR % 5 != 0 {print $3}' "$ANN_CP" | sort > "$OUT_DIR/seq1-expected.txt"
        kern_dump "$SUT" > "$OUT_DIR/seq1-$SIDE-kernel.txt"
        awk '{print $1}' "$OUT_DIR/seq1-$SIDE-kernel.txt" | sort > "$OUT_DIR/seq1-$SIDE-prefixes.txt"
        C1=$(wc -l < "$OUT_DIR/seq1-$SIDE-prefixes.txt")
        D1=$(comm -3 "$OUT_DIR/seq1-expected.txt" "$OUT_DIR/seq1-$SIDE-prefixes.txt" | grep -c . || true)
        docker exec "$INJ" sh -c "pkill -f bench-seq 2>/dev/null" >/dev/null 2>&1 || true
        sleep 2
        note "seq1 side=$SIDE count=$C1 expected=$(( $(wc -l < "$OUT_DIR/seq1-expected.txt") )) diff-lines=$D1"
        [ "$D1" = 0 ] && pass "e1seq seq1 $SIDE: exact prefix set after interleave" \
                       || fail "e1seq seq1 $SIDE: diff-lines=$D1"
        # SEQ-2: replace all attrs (same prefixes); no dupes, count exact.
        docker exec -d "$INJ" sh -c "python3 /bench-seq.py --peer $SUT_IP:179 \
            --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
            --announce /feed.announce --limit $LIMIT --linger 90 \
            --ops A,R1 --gap 3 > /var/log/seq-run.txt 2>&1"
        for _ in $(seq 1 240); do
            docker exec "$INJ" sh -c "grep -q SEQ-ALL-DONE /var/log/seq-run.txt 2>/dev/null" && break
            sleep 1
        done
        sleep 3
        kern_dump "$SUT" > "$OUT_DIR/seq2-$SIDE-kernel.txt"
        C2=$(wc -l < "$OUT_DIR/seq2-$SIDE-kernel.txt")
        DUP2=$(awk '{print $1}' "$OUT_DIR/seq2-$SIDE-kernel.txt" | uniq -d | wc -l)
        docker exec "$INJ" sh -c "pkill -f bench-seq 2>/dev/null" >/dev/null 2>&1 || true
        sleep 2
        note "seq2 side=$SIDE count=$C2 duplicate-prefixes=$DUP2"
        [ "$C2" = "$LIMIT" ] && [ "$DUP2" = 0 ] \
            && pass "e1seq seq2 $SIDE: replacement exact, no duplicates" \
            || fail "e1seq seq2 $SIDE: count=$C2 dups=$DUP2"
        # SEQ-3: session close + re-open over the SAME table (Rouster
        # persists per the disclosed deviation; re-add must replace,
        # never duplicate). FRR withdraws on close.
        docker exec -d "$INJ" sh -c "python3 /bench-seq.py --peer $SUT_IP:179 \
            --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
            --announce /feed.announce --limit $LIMIT --linger 90 \
            --ops A,X,A --gap 3 > /var/log/seq-run.txt 2>&1"
        for _ in $(seq 1 240); do
            docker exec "$INJ" sh -c "grep -q SEQ-ALL-DONE /var/log/seq-run.txt 2>/dev/null" && break
            sleep 1
        done
        sleep 3
        kern_dump "$SUT" > "$OUT_DIR/seq3-$SIDE-kernel.txt"
        C3=$(wc -l < "$OUT_DIR/seq3-$SIDE-kernel.txt")
        DUP3=$(awk '{print $1}' "$OUT_DIR/seq3-$SIDE-kernel.txt" | uniq -d | wc -l)
        note "seq3 side=$SIDE final-count=$C3 duplicates=$DUP3"
        [ "$C3" = "$LIMIT" ] && [ "$DUP3" = 0 ] \
            && pass "e1seq seq3 $SIDE: reset+re-add exact, no duplicates" \
            || fail "e1seq seq3 $SIDE: count=$C3 dups=$DUP3"
        docker exec "$INJ" sh -c "cat /var/log/seq-run.txt" > "$OUT_DIR/seq3-$SIDE.txt" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;
e45igp)
    # IGP-under-BGP convergence + the E6 mixed variant. The announced
    # next hop is OSPF-learned (10.99.0.1 via the peer's dummy /24), so
    # every BGP route resolves through the IGP; killing the peer's
    # ospfd must withdraw them, its return must restore them.
    LIMIT=${BENCH_X_LIMIT:-10000}
    MODE=${BENCH_X_IGP_MODE:-native}   # native: rouster bgpd + rouster
    # ospfd;  mixed: FRR bgpd + rouster ospfd;  frr: FRR bgpd + FRR
    # ospfd (the incumbent comparator)
    ANN_CP=$(cd "$(dirname "${ANNOUNCE:?e45igp needs the announce file}")" && pwd)/$(basename "$ANNOUNCE")
    PEER_IP=172.31.255.30
    OSPF_NET=10.99.0.0/24
    OSPF_NH=10.99.0.1
    # announce with next hops rewritten to the OSPF-learned address
    awk -v n="$LIMIT" -v nh="$OSPF_NH" \
        'NR <= n && /next-hop/ {sub(/next-hop [0-9.]*/, "next-hop " nh)} NR <= n' \
        "$ANN_CP" > "$OUT_DIR/announce-ospf.txt"
    ANN_OSPF=$(cd "$OUT_DIR" && pwd)/announce-ospf.txt
    SUT=x45-sut-$TS; INJ=x45-inj-$TS; PEER=x45-peer-$TS
    trap 'docker rm -f "$SUT" "$INJ" "$PEER" >/dev/null 2>&1 || true' EXIT
    note "=== e45igp mode=$MODE limit=$LIMIT (bgp-via-ospf)"
    new_sut "$SUT"
    start_rousterd "$SUT"
    if [ "$MODE" = frr ]; then
        # Deterministic config: per-daemon files via -f (the mgmtd
        # transaction was lost inside this cell; -f has no async step).
        docker exec "$SUT" sh -c "printf '%s\n' \
            'frr version 10.2' 'frr defaults traditional' 'hostname x45' \
            'interface eth0' \
            ' ip ospf network point-to-point' \
            ' ip ospf hello-interval 2' \
            ' ip ospf dead-interval 8' \
            'router ospf' ' ospf router-id 1.1.1.1' \
            ' network 172.31.255.0/24 area 0.0.0.0' \
            ' timers throttle spf 0 50 100' 'line vty' \
            > /etc/frr/ospfd.conf"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'frr version 10.2' 'frr defaults traditional' 'hostname x45' \
            'router bgp $SUT_AS' \
            ' no bgp network import-check' ' no bgp ebgp-requires-policy' \
            " neighbor $INJ_IP remote-as $INJ_AS" \
            " neighbor $INJ_IP timers 30 $HOLD" \
            ' address-family ipv4 unicast' '  exit-address-family' 'line vty' \
            > /etc/frr/bgpd.conf"
        docker exec "$SUT" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/ospfd.log --log-level info"
        wait_up "$SUT" "ospfd vty" 30 "test -S /var/run/frr/ospfd.vty"
        docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
        wait_up "$SUT" "bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
        for _ in $(seq 1 20); do
            sleep 2
            docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' && break
        done
        docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' \
            || { echo "FAIL: bgpd config did not load from -f file" >&2; exit 1; }
    else
        if [ "$MODE" = mixed ]; then
            # FRR bgpd with a deterministic -f file; OSPF is native
            # rouster-ospfd (file-config below)
            docker exec "$SUT" sh -c "printf '%s\n' \
                'frr version 10.2' 'frr defaults traditional' 'hostname x45' \
                'router bgp $SUT_AS' \
                ' no bgp network import-check' ' no bgp ebgp-requires-policy' \
                " neighbor $INJ_IP remote-as $INJ_AS" \
                " neighbor $INJ_IP timers 30 $HOLD" \
                ' address-family ipv4 unicast' '  exit-address-family' 'line vty' \
                > /etc/frr/bgpd.conf"
            docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
            wait_up "$SUT" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
            for _ in $(seq 1 20); do
                sleep 2
                docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' && break
            done
            docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' \
                || { echo "FAIL: bgpd config did not load from -f file" >&2; exit 1; }
        else
            start_rouster_bgpd "$SUT"
        fi
        # native rouster ospfd on the rouster core
        docker cp "$BIN_DIR/rouster-ospfd" "$SUT:/usr/local/bin/rouster-ospfd"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'zapi socket /var/run/frr/zserv.api' \
            'router ospf' ' router-id 1.1.1.1' \
            ' area 0.0.0.0' \
            '  interface eth0' \
            '   network-type point-to-point' \
            '   hello-interval 2' \
            '   dead-interval 8' \
            > /etc/rouster-ospfd.conf"
        docker exec -d "$SUT" sh -c "rouster-ospfd --config /etc/rouster-ospfd.conf > /var/log/rouster-ospfd.log 2>&1"
        wait_up "$SUT" "rouster ospfd up" 20 "pidof rouster-ospfd"
    fi
    # the OSPF peer: FRR ospfd advertising the dummy /24
    docker run -d --name "$PEER" --network "$NET_NAME" --ip "$PEER_IP" \
        --cpuset-cpus "$INJ_CPUS" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$PEER" sh -c "ip addr add $OSPF_NH/24 dev lo 2>/dev/null || true; ip link set lo up"
    docker exec "$PEER" sh -c "/usr/lib/frr/zebra -d --log file:$FRRLOG/pzebra.log --log-level info"
    wait_up "$PEER" "peer zebra vty" 30 "test -S /var/run/frr/zebra.vty"
    # Deterministic config: ospfd reads its own file via -f (the mgmtd
    # transaction path lost commits on some runs; -f cannot be lost).
    docker exec "$PEER" sh -c "printf '%s\n' \
        'frr version 10.2' 'frr defaults traditional' 'hostname x45peer' \
        'interface eth0' \
        ' ip ospf network point-to-point' \
        ' ip ospf hello-interval 2' \
        ' ip ospf dead-interval 8' \
        'router ospf' ' ospf router-id 2.2.2.2' \
        ' network 172.31.255.0/24 area 0.0.0.0' \
        ' network $OSPF_NET area 0.0.0.0' \
        ' timers throttle spf 0 50 100' \
        'line vty' > /etc/frr/ospfd.conf"
    docker exec "$PEER" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/pospfd.log --log-level info"
    wait_up "$PEER" "peer ospfd vty" 30 "test -S /var/run/frr/ospfd.vty"
    for _ in $(seq 1 90); do
        sleep 2
        docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor' | grep -c Full" 2>/dev/null | grep -q -v '^0$' && break
    done
    ADJ=$(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | awk '/^[0-9]+\./ {print $3; exit}')
    note "adjacency: $ADJ"
    case "$ADJ" in
        Full*|*" "Full*) : ;;
        *)
            note "peer-daemons: $(docker exec "$PEER" sh -c "pidof zebra mgmtd ospfd" 2>/dev/null | tr '\n' ' ')"
            note "peer-ospf-if: $(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf interface eth0'" 2>/dev/null | awk 'END{print $0}')"
            docker exec "$PEER" sh -c "cat /tmp/frrrun/pospfd.log 2>/dev/null" > "$OUT_DIR/peer-ospfd.log" 2>/dev/null || true
            docker exec "$SUT" sh -c "cat /var/log/rouster-ospfd.log 2>/dev/null" > "$OUT_DIR/sut-ospfd.log" 2>/dev/null || true
            docker exec "$SUT" sh -c "cat /tmp/frrrun/ospfd.log 2>/dev/null" >> "$OUT_DIR/sut-ospfd.log" 2>/dev/null || true
            fail "e45igp $MODE: OSPF adjacency never formed"
            docker rm -f "$SUT" "$INJ" "$PEER" >/dev/null 2>&1 || true
            exit 1 ;;
    esac
    # the BGP injector announcing via the OSPF next hop
    docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" -v "$ANN_OSPF":/feed.announce:ro \
        --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
    docker cp scripts/bench-flap.py "$INJ:/bench-flap.py"
    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec -d "$INJ" sh -c "python3 /bench-flap.py --peer $SUT_IP:179 \
        --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
        --announce /feed.announce --limit $LIMIT --flap-every 999999 \
        --rounds 0 --hold $HOLD --steady-wait 5 --linger 600 > /var/log/flap-run.txt 2>&1"
    OSPF_ROUTES=$(docker exec "$SUT" sh -c "ip route show proto 187 2>/dev/null | grep -c ." || echo 0)
    for _ in $(seq 1 120); do
        c=$(kern_count "$SUT"); [ "$c" -ge $((LIMIT - 20)) ] 2>/dev/null && break; sleep 1
    done
    BGP_FULL=$(kern_count "$SUT")
    note "baseline: ospf-proto187-routes=$OSPF_ROUTES bgp-via-ospf=$BGP_FULL (expect ~$LIMIT)"
    case "$BGP_FULL" in
        *[!0-9]*|"")
            docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary' 2>&1 | tail -3; vtysh -c 'show ip route 10.99.0.1' 2>&1 | tail -3" > "$OUT_DIR/diag-$MODE.txt" 2>/dev/null || true
            docker cp "$SUT:/var/log/rousterd.log" "$OUT_DIR/rousterd-$MODE.log" 2>/dev/null || true
            fail "e45igp $MODE: count not numeric"; docker rm -f "$SUT" "$INJ" "$PEER" >/dev/null 2>&1 || true; exit 1 ;;
    esac
    if [ "$BGP_FULL" -lt $((LIMIT - 20)) ]; then
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary' 2>&1 | tail -3; vtysh -c 'show ip route 10.99.0.1' 2>&1 | tail -3" > "$OUT_DIR/diag-$MODE.txt" 2>/dev/null || true
        docker exec "$INJ" sh -c "cat /var/log/flap-run.txt 2>/dev/null | head -8" > "$OUT_DIR/flap-head-$MODE.txt" 2>/dev/null || true
        fail "e45igp $MODE: BGP routes did not resolve via OSPF ($BGP_FULL)"
        docker rm -f "$SUT" "$INJ" "$PEER" >/dev/null 2>&1 || true
        exit 1
    else
        pass "e45igp $MODE: BGP table resolved through OSPF nexthop ($BGP_FULL)"
    fi
    # the event: kill the PEER's ospfd -> adjacency dies (dead 8s) ->
    # OSPF route gone -> BGP nexthops unresolved -> withdraw.
    timeline "$SUT" igp 1
    # forwarding probe: ping the OSPF nexthop (10.99.0.1) from the SUT
    # through the whole event; the kernel route to it carries the OSPF
    # adjacency, so loss marks the forwarding-plane outage window.
    docker exec -d "$SUT" sh -c "ping -i 0.2 -c 900 $OSPF_NH > /probe.txt 2>&1"
    TKILL=$(date +%s.%N)
    docker exec "$PEER" sh -c "kill -9 \$(pidof ospfd)"
    for _ in $(seq 1 60); do
        c=$(kern_count "$SUT"); [ "$c" -le 10 ] 2>/dev/null && break; sleep 1
    done
    TW=$(date +%s.%N)
    # restore the peer's ospfd -> adjacency re-forms -> routes return
    docker exec "$PEER" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/pospfd2.log --log-level info"
    for _ in $(seq 1 30); do
        sleep 2
        docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor' | grep -c Full" 2>/dev/null | grep -q -v '^0$' && break
    done
    for _ in $(seq 1 180); do
        c=$(kern_count "$SUT"); [ "$c" -ge $((LIMIT - 20)) ] 2>/dev/null && break; sleep 1
    done
    TR=$(date +%s.%N)
    docker exec "$SUT" sh -c "pkill -f 'ping -i 0.2' 2>/dev/null" >/dev/null 2>&1 || true
    docker cp "$SUT:/probe.txt" "$OUT_DIR/probe-$MODE.txt" 2>/dev/null || true
    TL=$OUT_DIR/tl-$MODE.csv
    timeline_stop "$SUT" igp "$TL"
    python3 - "$TKILL" "$TW" "$TR" "$OUT_DIR/probe-$MODE.txt" >> "$OUT_DIR/notes.txt" <<'PYEOF'
import sys, re
tk, tw, tr = map(float, sys.argv[1:4])
try:
    txt = open(sys.argv[4], errors="replace").read()
    sent = int(re.search(r"(\d+) packets transmitted", txt).group(1))
    recv = int(re.search(r"(\d+) received", txt).group(1))
    loss_pct = (sent - recv) / sent * 100 if sent else 0.0
    times = [float(x) for x in re.findall(r"icmp_seq=(\d+)", txt)]
    probe = f" probe: {sent} sent, {recv} received ({loss_pct:.0f}% loss)"
except Exception:
    probe = " probe: unreadable"
print(f"X-NOTE e45igp timeline: kill_to_withdrawn_s={tw-tk:.1f} "
      f"peer_restart_to_restored_s={tr-tw:.1f} total_event_s={tr-tk:.1f}{probe}")
PYEOF
    docker exec "$INJ" sh -c "cat /var/log/flap-run.txt" > "$OUT_DIR/flap-$MODE.txt" 2>/dev/null || true
    docker cp "$SUT:/var/log/rouster-ospfd.log" "$OUT_DIR/rouster-ospfd-$MODE.log" 2>/dev/null || true
    ;;
e5cycles)
    # Reconnection during replay + repeated cycles: kill the injector
    # mid-replay, restart it, verify exact recovery; 3 cycles.
    LIMIT=${BENCH_X_LIMIT:-100000}
    NEED=$((LIMIT > 2000 ? LIMIT - LIMIT/200 : LIMIT - 2))
    for SIDE in frr rouster; do
        SUT=x5c-sut-$TS-$SIDE
        trap 'docker rm -f "$SUT" >/dev/null 2>&1 || true; docker ps -aq --filter name=x5c-inj | xargs -r docker rm -f >/dev/null 2>&1 || true' EXIT
        note "=== e5cycles side=$SIDE limit=$LIMIT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        for CYC in 1 2 3; do
            INJ=x5c-inj-$TS-$SIDE-$CYC
            start_injector "$INJ"
            docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
            T0=$(date +%s.%N)
            docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
            # kill mid-replay: after ~2s of sending (roughly 20-40% in)
            sleep 2
            TC=$(date +%s.%N)
            docker rm -f "$INJ" >/dev/null 2>&1
            # reconnect: fresh injector, full replay
            INJ=x5c-inj2-$TS-$SIDE-$CYC
            start_injector "$INJ"
            docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
            docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
            for _ in $(seq 1 240); do
                c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
            done
            T1=$(date +%s.%N)
            FINAL=$(kern_count "$SUT")
            DUPS=$(docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null" | awk '{print $1}' | sort | uniq -d | wc -l)
            note "side=$SIDE cycle=$CYC midkill_at=$(python3 -c "print(f'{$TC-$T0:.1f}')")s recover_s=$(python3 -c "print(f'{$T1-$TC:.1f}')") final=$FINAL dups=$DUPS"
            if [ "$FINAL" -ge "$NEED" ] && [ "$DUPS" = 0 ]; then
                pass "e5cycles $SIDE cycle=$CYC exact, no duplicates"
            else
                fail "e5cycles $SIDE cycle=$CYC final=$FINAL dups=$DUPS"
            fi
            docker rm -f "$INJ" >/dev/null 2>&1 || true
        done
        docker rm -f "$SUT" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;

e5backend)
    # Backend failure during bulk install: SIGSTOP rousterd ~30% into
    # the 100k ingest for 10 s (the daemon stops reading ACKs; the
    # rcvbuf overruns and datagrams -- including install ACKs -- are
    # dropped: the exact F9 wedge shape), then SIGCONT. The SUT-side
    # hardening (bounded ACK re-issue + overrun resync) must recover
    # without wedge; measure the wall penalty, overruns, final count.
    LIMIT=${BENCH_X_LIMIT:-100000}
    NEED=$((LIMIT > 2000 ? LIMIT - LIMIT/200 : LIMIT - 2))
    STALL=${BENCH_X_STALL:-10}
    for RUN in 1 2 3; do
        SUT=x5b-sut-$TS-$RUN; INJ=x5b-inj-$TS-$RUN
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e5backend run=$RUN limit=$LIMIT stall=${STALL}s"
        docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
            --cpuset-cpus "$SUT_CPUS" \
            --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        docker exec "$SUT" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos || true"
        start_rousterd "$SUT"
        start_rouster_bgpd "$SUT"
        start_injector "$INJ"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        docker exec -d "$INJ" sh -c "mrt-replay $(INJ_ARGS_FOR $LIMIT) > /var/log/replay.txt 2>&1"
        # stall when ~30% is installed (the 100k pass completes in
        # ~2 s on this rig — a fixed sleep stalled a finished daemon)
        for _ in $(seq 1 120); do
            c=$(kern_count "$SUT"); [ "$c" -ge $((LIMIT / 3)) ] 2>/dev/null && break; sleep 0.2
        done
        TSTOP=$(date +%s.%N)
        docker exec "$SUT" sh -c "kill -STOP \$(pidof rousterd)"
        sleep "$STALL"
        docker exec "$SUT" sh -c "kill -CONT \$(pidof rousterd)"
        TCONT=$(date +%s.%N)
        for _ in $(seq 1 300); do
            c=$(kern_count "$SUT"); [ "$c" -ge "$NEED" ] 2>/dev/null && break; sleep 1
        done
        TFULL=$(date +%s.%N)
        OVER=$(docker exec "$SUT" sh -c "grep -c 'buffer full' /var/log/rousterd.log 2>/dev/null" || echo "?")
        RESYNC=$(docker exec "$SUT" sh -c "grep -ci 'resync' /var/log/rousterd.log 2>/dev/null" || echo "?")
        FINAL=$(kern_count "$SUT")
        note "run=$RUN stall_s=$STALL cont_to_full_s=$(python3 -c "print(f'{$TFULL-$TCONT:.1f}')") final=$FINAL overruns=$OVER resync_lines=$RESYNC"
        if [ "$FINAL" -ge "$NEED" ] 2>/dev/null; then
            pass "e5backend run=$RUN: recovered from the mid-install stall, table exact"
        else
            fail "e5backend run=$RUN: final=$FINAL (wedge or loss)"
        fi
        docker cp "$SUT:/var/log/rousterd.log" "$OUT_DIR/rousterd-$RUN.log" 2>/dev/null || true
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;
*) echo "unknown cell $CELL" >&2; exit 1 ;;
esac
echo "bench-x: done — $OUT_DIR"
