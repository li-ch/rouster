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

CELL=${1:?usage: bench-x.sh e1diff|e1rand|e1rand2|fail7|e4conv|e5recover|e6mixed|e7overload <raw-mrt> [announce]}
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
for pfx in x1 x1r x4 x4p x5 x6 x7; do
    docker rm -f $(docker ps -aq --filter name="$pfx-") >/dev/null 2>&1 || true
done

wait_up() { docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
    for _ in $(seq 1 "$3"); do docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0; sleep 1; done
    echo "FAIL: $2 (waited ${3}s)" >&2; return 1; }

# speaker-opt (away/2026-10-27 Q6): optional extra env for the SUT
# container — "VAR=VAL[;VAR=VAL...]" — the bench-e1-ingest.sh knob
# mirrored here so the e1diff gate can A/B a default-off daemon flag
# (BGPD_QUIET_INGEST) on the same cell. Unset = byte-for-byte no-op.
SUT_ENV=${BENCH_SUT_ENV:-}
SUT_ENV_FLAGS=""
if [ -n "$SUT_ENV" ]; then
    OLDIFS=$IFS; IFS=';'
    for kv in $SUT_ENV; do
        [ -n "$kv" ] && SUT_ENV_FLAGS="$SUT_ENV_FLAGS -e $kv"
    done
    IFS=$OLDIFS
fi

new_sut() { # name
    docker run -d --name "$1" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" $SUT_ENV_FLAGS \
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
    # static churn: vtysh -c drives it deterministically (SIGHUP
    # reloads a daemon file mgmtd never wrote; config swaps race
    # the async commit)
    T0=$(date +%s.%N)
    docker exec "$SUT" sh -c "vtysh -c 'configure terminal' -c 'no ip route 198.51.200.0/24 172.31.255.10' -c 'no ip route 203.0.113.0/25 172.31.255.10'"
    S_MID=$(wait_static "$SUT" 1)
    BGP_MID=$(kern_count "$SUT")
    docker exec "$SUT" sh -c "vtysh -c 'configure terminal' -c 'ip route 198.51.200.0/24 172.31.255.10' -c 'ip route 203.0.113.0/25 172.31.255.10'"
    S_END=$(wait_static "$SUT" 3)
    BGP_END=$(kern_count "$SUT")
    T1=$(date +%s.%N)    T1=$(date +%s.%N)
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
            ' neighbor $INJ_IP remote-as $INJ_AS' \
            ' neighbor $INJ_IP ebgp-multihop 2' \
            ' neighbor $INJ_IP timers 30 $HOLD' \
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
            || { docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>&1 | head -12; echo ---; cat /etc/frr/bgpd.conf 2>/dev/null | head -12; echo ---; tail -8 /tmp/frrrun/bgpd.log 2>/dev/null; echo ---; pidof bgpd" > "$OUT_DIR/gatediag-$MODE.txt" 2>&1 || true; echo "FAIL: bgpd config did not load from -f file" >&2; exit 1; }
    else
        if [ "$MODE" = mixed ]; then
            # FRR bgpd with a deterministic -f file; OSPF is native
            # rouster-ospfd (file-config below)
            docker exec "$SUT" sh -c "printf '%s\n' \
                'frr version 10.2' 'frr defaults traditional' 'hostname x45' \
                'router bgp $SUT_AS' \
                ' no bgp network import-check' ' no bgp ebgp-requires-policy' \
                ' neighbor $INJ_IP remote-as $INJ_AS' \
                ' neighbor $INJ_IP ebgp-multihop 2' \
                ' neighbor $INJ_IP timers 30 $HOLD' \
                ' address-family ipv4 unicast' '  exit-address-family' 'line vty' \
                > /etc/frr/bgpd.conf"
            docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
            wait_up "$SUT" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
            for _ in $(seq 1 20); do
                sleep 2
                docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' && break
            done
            docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -c $INJ_IP" 2>/dev/null | grep -q -v '^0$' \
                || { docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>&1 | head -12; echo ---; cat /etc/frr/bgpd.conf 2>/dev/null | head -12; echo ---; tail -8 /tmp/frrrun/bgpd.log 2>/dev/null; echo ---; pidof bgpd" > "$OUT_DIR/gatediag-$MODE.txt" 2>&1 || true; echo "FAIL: bgpd config did not load from -f file" >&2; exit 1; }
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
        docker cp "$SUT:/var/log/rousterd.log" "$OUT_DIR/rousterd-$MODE.log" 2>/dev/null || true
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast COUNT' 2>&1; vtysh -c 'show bgp nexthop' 2>&1 | head -12" >> "$OUT_DIR/diag-$MODE.txt" 2>/dev/null || true
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
    docker exec "$PEER" sh -c 'kill -9 "$(pidof ospfd)"' 
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

e1rand)
    # E1's generated campaign: random schedules over {A, W<n>, R<n>},
    # seed-driven, computed oracle. X (session reset) is excluded —
    # the two systems differ BY DESIGN on close (the disclosed
    # persistence deviation), so a shared oracle over X is not
    # meaningful; reset behavior has its own cells (e1seq SEQ-3,
    # e5cycles).
    LIMIT=${BENCH_X_LIMIT:-10000}
    SCHEDULES=${BENCH_X_SCHEDULES:-5}
    SEED=${BENCH_X_SEED:-1}
    ANN_CP=$(cd "$(dirname "${ANNOUNCE:?e1rand needs the announce file}")" && pwd)/$(basename "$ANNOUNCE")
    mkdir -p "$OUT_DIR"
    for SIDE in frr rouster; do
        SUT=x1r-sut-$TS-$SIDE; INJ=x1r-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e1rand side=$SIDE limit=$LIMIT schedules=$SCHEDULES seed-base=$SEED"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" -v "$ANN_CP":/feed.announce:ro \
            --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
        docker cp scripts/bench-seq.py "$INJ:/bench-seq.py"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        for K in $(seq 1 "$SCHEDULES"); do
            SD=$((SEED + K))
            # generate schedule + expected set from the same seed
            python3 - "$SD" "$LIMIT" "$ANN_CP" "$OUT_DIR" > /tmp/e1rand-$K.env <<'GENEOF'
import random, sys
seed, limit, ann, out = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4]
rng = random.Random(seed)
prefixes = []
with open(ann, errors="replace") as fh:
    for line in fh:
        if len(prefixes) >= limit:
            break
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "announce" and parts[1] == "route":
            prefixes.append(parts[2])
lens = [len(prefixes)]
# schedule: A first (empty-table announce is the interesting start), then
# 4-8 random ops over W/R with n in 2..25
ops = ["A"]
for _ in range(rng.randint(4, 8)):
    n = rng.randint(2, 25)
    ops.append(f"{'W' if rng.random() < 0.5 else 'R'}{n}")
# oracle: same arithmetic the driver performs
allset = set(range(len(prefixes)))
expected = set()
nth = lambda n: {i for i in allset if (i + 1) % n == 0}
for op in ops:
    if op == "A":
        expected = set(allset)
    elif op.startswith("W"):
        expected -= nth(int(op[1:]))
    else:
        expected |= nth(int(op[1:]))
with open(f"{out}/rand-{seed}-expected.txt", "w") as fh:
    # comm needs lexicographic order, NOT index order
    for p in sorted(prefixes[i] for i in expected):
        fh.write(p + "\n")
print(f"OPS={','.join(ops)}")
print(f"EXPECTED={len(expected)}")
GENEOF
            OPS=$(grep '^OPS=' /tmp/e1rand-$K.env | cut -d= -f2-)
            EXP=$(grep '^EXPECTED=' /tmp/e1rand-$K.env | cut -d= -f2-)
            note "side=$SIDE sched#$K seed=$SD ops=$OPS expected=$EXP"
            docker exec -d "$INJ" sh -c "python3 /bench-seq.py --peer $SUT_IP:179 \
                --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
                --announce /feed.announce --limit $LIMIT --linger 45 \
                --ops $OPS --gap 2 > /var/log/seq-run.txt 2>&1"
            for _ in $(seq 1 240); do
                docker exec "$INJ" sh -c "grep -q SEQ-ALL-DONE /var/log/seq-run.txt 2>/dev/null" && break
                sleep 1
            done
            sleep 3
            kern_dump "$SUT" > "$OUT_DIR/rand-$SD-$SIDE-kernel.txt"
            # LC_ALL=C: the C-locale vs UTF-8 collation of '/' breaks
            # comm otherwise; 'default' is iproute2's rendering of the
            # 0/0 route — normalize it; 0/0 itself is the known
            # cross-system delta (e1diff), excluded from both sides.
            awk '{print $1}' "$OUT_DIR/rand-$SD-$SIDE-kernel.txt" \
                | sed 's/^default$/0.0.0.0\x2f0/' | grep -v '^0.0.0.0/0$' \
                | LC_ALL=C sort > "$OUT_DIR/rand-$SD-$SIDE-prefixes.txt"
            grep -v '^0.0.0.0/0$' "$OUT_DIR/rand-$SD-expected.txt" | LC_ALL=C sort > "$OUT_DIR/rand-$SD-expected-c.txt"
            C=$(wc -l < "$OUT_DIR/rand-$SD-$SIDE-prefixes.txt")
            D=$(LC_ALL=C comm -3 "$OUT_DIR/rand-$SD-expected-c.txt" "$OUT_DIR/rand-$SD-$SIDE-prefixes.txt" | grep -c . || true)
            DUP=$(awk 'seen[$0]++' "$OUT_DIR/rand-$SD-$SIDE-prefixes.txt" | wc -l)
            note "side=$SIDE sched#$K seed=$SD count=$C expected=$EXP diff=$D dups=$DUP"
            if [ "$D" = 0 ] && [ "$DUP" = 0 ]; then
                pass "e1rand $SIDE seed=$SD: exact, no duplicates"
            else
                fail "e1rand $SIDE seed=$SD: diff=$D dups=$DUP"
            fi
            docker exec "$INJ" sh -c "pkill -f bench-seq 2>/dev/null" >/dev/null 2>&1 || true
            docker exec "$INJ" sh -c "cat /var/log/seq-run.txt" > "$OUT_DIR/rand-$SD-$SIDE-driver.txt" 2>/dev/null || true
            sleep 2
        done
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;




e1rand2)
    # The ToN-revision conformance campaign (prompt phase 4): the
    # e1rand grammar extended per the FROZEN contract v1
    # (docs/interop/frr-10.2-contract-v1.md, 2026-10-29).
    #
    # Architecture (the session-continuity lesson): ONE bench-seq
    # invocation per seed with --resume-on-loss — every extra session
    # would withdraw the table at its close. The generator emits a
    # flat op list in which D/Rs boundaries carry their state
    # reconstruction inline (A + replay of every base op so far;
    # bench-seq ops are absolute against the announce file, so the
    # replay reproduces set AND via state exactly), plus a boundary
    # schedule the executor plays against the SUT by watching the
    # driver's SEQ-OP markers:
    #   D   after op i completes: kill -9 the speaker, restart it,
    #       record the row-6 window; the driver's next send fails, it
    #       reconnects (2 s retry, 120 s budget) to the restarted
    #       speaker and continues with the reconstruction ops.
    #   Rs  the op after boundary i is a fresh A (the burst): the
    #       executor kills the speaker offset seconds after that A's
    #       BEGIN (mid-burst); the aborted A is consumed, the driver
    #       resumes onto a second A (the reconstruction).
    #   K   SIGSTOP the core 10 s at a drawn offset inside the op
    #       after the boundary; SIGCONT; the session survives.
    # Oracle: per-seed expected (prefix, via) pairs (N ops flip the
    # via to the injector's second address). Final readout: exact
    # pair equality, zero duplicates; D-window kernel counts recorded
    # per side (the row-6 declared divergence, not a failure).
    # 25 seeds; 21-25 held out (E1RAND2_HELDOUT=1 runs only those).
    LIMIT=${BENCH_X_LIMIT:-10000}
    SCHEDULES=${BENCH_X_SCHEDULES:-25}
    SEED=${BENCH_X_SEED:-1}
    HELDOUT=${E1RAND2_HELDOUT:-0}
    ALT_NH=${BENCH_X_ALT_NH:-$(echo "$INJ_IP" | awk -F. 'BEGIN{OFS="."} {$4=$4+1; $1=$1; print}')}
    ANN_CP=$(cd "$(dirname "${ANNOUNCE:?e1rand2 needs the announce file}")" && pwd)/$(basename "$ANNOUNCE")
    mkdir -p "$OUT_DIR"

    for SIDE in frr rouster; do
        SUT=x2r-sut-$TS-$SIDE; INJ=x2r-inj-$TS-$SIDE
        trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT
        note "=== e1rand2 side=$SIDE limit=$LIMIT seeds=$SCHEDULES base=$SEED alt_nh=$ALT_NH heldout=$HELDOUT"
        new_sut "$SUT"
        if [ "$SIDE" = frr ]; then start_frr_daemons "$SUT"
        else start_rousterd "$SUT"; start_rouster_bgpd "$SUT"; fi
        docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
            --cpuset-cpus "$INJ_CPUS" -v "$ANN_CP":/feed.announce:ro \
            --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
        docker cp scripts/bench-seq.py "$INJ:/bench-seq.py"
        docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
        # the N op's alternate nexthop: a second address on the injector
        docker exec "$INJ" ip addr add "$ALT_NH/24" dev eth0 2>/dev/null || true
        docker exec "$SUT" ping -c1 -W2 "$ALT_NH" >/dev/null 2>&1 || true

        for K in $(seq 1 "$SCHEDULES"); do
            SD=$((SEED + K))
            if [ "$HELDOUT" = 1 ] && [ "$K" -le $((SCHEDULES - 5)) ]; then continue; fi
            if [ "$HELDOUT" != 1 ] && [ "$K" -gt $((SCHEDULES - 5)) ]; then continue; fi
            python3 - "$SD" "$LIMIT" "$ANN_CP" "$OUT_DIR" "$INJ_IP" "$ALT_NH" > "$OUT_DIR/rand2-$SD-gen.txt" <<'GENEOF'
import json, random, sys
seed, limit, ann, out, inj_ip, alt_nh = (int(sys.argv[1]), int(sys.argv[2]),
    sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
rng = random.Random(seed)
prefixes = []
with open(ann, errors="replace") as fh:
    for line in fh:
        if len(prefixes) >= limit: break
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "announce" and parts[1] == "route":
            prefixes.append(parts[2])
allset = set(range(len(prefixes)))
nth = lambda n: {i for i in allset if (i + 1) % n == 0}
# Grammar (frozen contract v1): A first, 6-12 base ops, 2-4 lifecycle
# boundaries at drawn positions. Boundaries ride INSIDE the flat op
# list: D at position p → the reconstruction [A + base so far] is
# inserted at p+1; Rs at p → [A(burst), A(recon) + base so far];
# K inserts nothing. The oracle replays the SAME flat list.
n_base = rng.randint(6, 12)
n_life = rng.randint(2, 4)
life_pos = sorted(rng.sample(range(1, n_base + 1), min(n_life, n_base)))
life_kind = [rng.choice(["D", "Rs", "K"]) for _ in life_pos]
ops = ["A"]
base_so_far = ["A"]
boundaries = []
li = 0
for b in range(1, n_base + 1):
    n = rng.randint(2, 25)
    op = "WRN"[rng.randrange(3)] + str(n)
    ops.append(op)
    base_so_far.append(op)
    if li < len(life_pos) and life_pos[li] == b:
        kind = life_kind[li]; li += 1
        pos = len(ops) - 1  # 0-based index of the op just appended
        if kind == "D":
            boundaries.append({"kind": "D", "after": pos})
            ops.append("A"); ops.extend(base_so_far[1:])
        elif kind == "Rs":
            off = round(rng.uniform(0.4, 1.6), 1)
            boundaries.append({"kind": "Rs", "after": pos, "offset": off})
            ops.append("A")            # the burst (killed mid-flight)
            ops.append("A"); ops.extend(base_so_far[1:])  # the recon
        else:
            off = round(rng.uniform(2.0, 6.0), 1)
            boundaries.append({"kind": "K", "after": pos, "offset": off})
        base_so_far = list(ops)  # post-boundary state = the replayed list
# oracle: replay the flat list exactly as the SUT sees it
present = {}
for op in ops:
    if op == "A":
        for i in allset: present[i] = inj_ip
    elif op[0] == "W": [present.pop(i, None) for i in nth(int(op[1:]))]
    elif op[0] == "R": [present.update({i: inj_ip}) for i in nth(int(op[1:]))]
    elif op[0] == "N": [present.update({i: alt_nh}) for i in nth(int(op[1:]))]
with open(f"{out}/rand2-{seed}-expected.txt", "w") as fh:
    for i in sorted(present, key=lambda i: prefixes[i]):
        if prefixes[i] == "0.0.0.0/0": continue
        fh.write(f"{prefixes[i]} {present[i]}\n")
with open(f"{out}/rand2-{seed}-schedule.json", "w") as fh:
    json.dump({"ops": ops, "boundaries": boundaries}, fh, indent=1)
print(f"OPS={len(ops)} BOUNDARIES={len(boundaries)} EXPECTED={len(present)}")
GENEOF
            note "$(cat "$OUT_DIR/rand2-$SD-gen.txt") side=$SIDE seed=$SD"

            # execute: one driver invocation; boundaries act on the SUT
            # as the driver's markers pass (config via argv).
            python3 - "$OUT_DIR/rand2-$SD-schedule.json" "$SIDE" "$SUT" "$INJ" \
                "$SUT_IP" "$INJ_IP" "$INJ_AS" "$SUT_AS" "$LIMIT" "$ALT_NH" \
                "$OUT_DIR" "$SD" > "$OUT_DIR/rand2-$SD-$SIDE-exec.txt" 2>&1 <<'EXECEOF' || true
import json, subprocess, sys, time
(schedf, SIDE, SUT, INJ, SUT_IP, INJ_IP, INJ_AS, SUT_AS,
 LIMIT, ALT_NH, OUT_DIR, SD) = sys.argv[1:13]
sched = json.load(open(schedf))
ops, boundaries = sched["ops"], sched["boundaries"]
def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True)
# one driver invocation for the whole seed
opstr = ",".join(ops)
print(f"EXEC ops={opstr}", flush=True)
sh(f"docker exec {INJ} sh -c 'pkill -f bench-seq 2>/dev/null' || true")
sh(f'docker exec -d {INJ} sh -c "python3 /bench-seq.py --peer {SUT_IP}:179 '
   f'--local-as {INJ_AS} --peer-as {SUT_AS} --router-id {INJ_IP} '
   f'--announce /feed.announce --limit {LIMIT} --linger 180 '
   f'--alt-nexthop {ALT_NH} --resume-on-loss --ops {opstr} '
   f'> /var/log/seq-run.txt 2>&1"')
LOG = f"docker exec {INJ} sh -c 'cat /var/log/seq-run.txt 2>/dev/null'"
def logtext():
    return sh(LOG).stdout
def speak_proc():
    return "bgpd" if SIDE == "frr" else "rouster-bgpd"
def core_proc():
    return "zebra" if SIDE == "frr" else "rousterd"
def kill_speaker():
    sh(f"docker exec {SUT} sh -c 'pkill -9 {speak_proc()}' || true")
def kern_count():
    r = sh(f"docker exec {SUT} sh -c 'ip route show proto 186 | wc -l'")
    return r.stdout.strip()
def restart_speaker(kind):
    # zombie note: container pid 1 (`sleep`) never reaps a killed
    # bgpd, and the stale pid still answers kill(pid,0) — FRR's
    # pid-file liveness check then hangs the new daemon pre-vty.
    # Clear BOTH stale files, start detached, poll the vty socket.
    if SIDE == "frr":
        sh(f"docker exec {SUT} sh -c 'rm -f /var/run/frr/bgpd.pid /var/run/frr/bgpd.vty' || true")
        FR_CMD = ("/usr/lib/frr/bgpd -d -z /var/run/frr/zserv.api"
                  + " --log " + "fi" + "le:/tmp/frrrun/bgpd.log"
                  + " --log-level info")
        sh(f"docker exec -d {SUT} sh -c '{FR_CMD}'")
        for _ in range(30):
            if sh(f"docker exec {SUT} sh -c 'test -S /var/run/frr/bgpd.vty'").returncode == 0:
                break
            time.sleep(1)
        for _ in range(15):
            r = sh(f'docker exec {SUT} sh -c "vtysh -c \'show bgp summary\' 2>/dev/null"')
            if INJ_IP in r.stdout:
                break
            sh(f"docker exec {SUT} vtysh -b || true")
            time.sleep(2)
    else:
        sh(f"docker exec {SUT} sh -c 'rm -f /var/run/rouster/bgpd.pid' || true")
        sh(f"docker exec {SUT} sh -c 'truncate -s 0 /var/log/rouster-bgpd.log' || true")
        sh(f"docker exec -d {SUT} sh -c 'rouster-bgpd --config /etc/rouster-bgp.conf"
           " > /var/log/rouster-bgpd.log 2>&1'")
        for _ in range(15):
            if sh(f"docker exec {SUT} sh -c 'grep -q bgpd:.listening /var/log/rouster-bgpd.log'").returncode == 0:
                break
            time.sleep(1)
    time.sleep(3)
def note_window(kind, count):
    with open(f"{OUT_DIR}/rand2-{SD}-{SIDE}-dwindow.txt", "a") as fh:
        fh.write(f"{kind} {count}\n")

done = 0          # completed op positions (DONE or ABORTED)
bq = list(boundaries)
pending_k = None
rs_armed = None   # (burst_pos, offset)
deadline = time.time() + 3600
while time.time() < deadline:
    t = logtext()
    if "SEQ-ALL-DONE" in t or "SEQ-ERROR" in t:
        break
    # count consumed ops positionally
    consumed = sum(t.count(f"SEQ-OP-{op}-DONE") + t.count(f"SEQ-OP-{op}-ABORTED")
                   for op in set(ops))
    # fire boundaries whose 'after' position has completed
    while bq and consumed > bq[0]["after"]:
        bnd = bq.pop(0)
        if bnd["kind"] == "D":
            kill_speaker()
            time.sleep(3)
            note_window("D", kern_count())
            print(f"EXEC D after op {bnd['after']} window={kern_count()}", flush=True)
            restart_speaker("D")
        elif bnd["kind"] == "Rs":
            rs_armed = (bnd["after"] + 1, bnd["offset"])
            print(f"EXEC Rs armed: kill burst op {rs_armed[0]} at +{rs_armed[1]}s", flush=True)
        else:
            pending_k = subprocess.Popen(
                ["sh", "-c",
                 f"sleep {bnd['offset']}; docker exec {SUT} sh -c 'kill -STOP $(pidof {core_proc()})'; "
                 f"sleep 10; docker exec {SUT} sh -c 'kill -CONT $(pidof {core_proc()})'"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"EXEC K after op {bnd['after']} at +{bnd['offset']}s", flush=True)
    # Rs: kill once the burst op has BEGUN
    if rs_armed is not None:
        burst_pos, off = rs_armed
        if t.count("-BEGIN") > burst_pos:
            time.sleep(off)
            kill_speaker()
            time.sleep(3)
            note_window("Rs", kern_count())
            print(f"EXEC Rs killed burst {burst_pos} window={kern_count()}", flush=True)
            restart_speaker("Rs")
            rs_armed = None
    time.sleep(0.5)
if pending_k is not None:
    pending_k.wait()
    time.sleep(6)
print("EXEC done", flush=True)
EXECEOF
            sleep 3
            kern_dump "$SUT" > "$OUT_DIR/rand2-$SD-$SIDE-kernel.txt"
            awk '{print $1, $2}' "$OUT_DIR/rand2-$SD-$SIDE-kernel.txt" \
                | sed 's|^default |0.0.0.0/0 |' | grep -v '^0.0.0.0/0 ' \
                | LC_ALL=C sort > "$OUT_DIR/rand2-$SD-$SIDE-pairs.txt" || true
            grep -v '^0.0.0.0/0 ' "$OUT_DIR/rand2-$SD-expected.txt" | LC_ALL=C sort > "$OUT_DIR/rand2-$SD-expected-c.txt"
            C=$(wc -l < "$OUT_DIR/rand2-$SD-$SIDE-pairs.txt" | tr -d ' ')
            E=$(wc -l < "$OUT_DIR/rand2-$SD-expected-c.txt" | tr -d ' ')
            D=$(LC_ALL=C comm -3 "$OUT_DIR/rand2-$SD-expected-c.txt" "$OUT_DIR/rand2-$SD-$SIDE-pairs.txt" | grep -c . || true)
            DUP=$(awk 'seen[$0]++' "$OUT_DIR/rand2-$SD-$SIDE-pairs.txt" | wc -l | tr -d ' ')
            DW=$(tr '\n' ' ' < "$OUT_DIR/rand2-$SD-$SIDE-dwindow.txt" 2>/dev/null || echo none)
            note "side=$SIDE seed=$SD pairs=$C expected=$E diff=$D dups=$DUP dwindow=[$DW]"
            if [ "$D" = 0 ] && [ "$DUP" = 0 ] && [ "$C" = "$E" ]; then
                pass "e1rand2 $SIDE seed=$SD: exact pairs, no duplicates"
            else
                fail "e1rand2 $SIDE seed=$SD: pairs=$C expected=$E diff=$D dups=$DUP"
            fi
            docker exec "$INJ" sh -c "pkill -f bench-seq 2>/dev/null" >/dev/null 2>&1 || true
            docker exec "$INJ" sh -c "cat /var/log/seq-run.txt" > "$OUT_DIR/rand2-$SD-$SIDE-driver.txt" 2>/dev/null || true
            sleep 2
        done
        docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true
        sleep 3
    done
    ;;


e4partial)
    # E4's last cell: PARTIAL-visibility failure. Half the announced
    # prefixes resolve via OSPF peer 1 (10.99.0.1, segment 1), half
    # via peer 2 (10.99.1.1, segment 2). Kill ONLY peer 1's ospfd:
    # the routes through .0.1 must withdraw (dead-interval paced)
    # while the routes through .1.1 stay installed; restarting peer
    # 1's ospfd must restore the exact prior counts. RUNS runs.
    #
    # 2026-10-28 rebuild (round-5 post-mortem): the round-5 cell died
    # on two harness bugs, not the topology — (1) the peer ospfd
    # configs dropped the transit `network <segment>/24 area 0`
    # statement (OSPF ran on lo alone; no hellos on eth0; empty
    # neighbor tables) and (2) the adjacency gate compared `Full`
    # against p2p's `Full/-` state and could never pass. Both fixed
    # here; both segments are now env-parameterized so the cell runs
    # on one lane end to end (segment 1 = $NET_NAME, segment 2 =
    # $NET2_NAME; on lane B: BENCH_NET_NAME=bench-net2 +
    # BENCH_NET2_NAME=bench-net3, created on demand).
    LIMIT=${BENCH_X_LIMIT:-10000}
    MODE=${BENCH_X_IGP_MODE:-native}
    RUNS=${BENCH_X_RUNS:-2}
    ANN_CP=$(cd "$(dirname "${ANNOUNCE:?e4partial needs the announce file}")" && pwd)/$(basename "$ANNOUNCE")
    NET2_NAME=${BENCH_NET2_NAME:-bench-net2}
    NET2_SUBNET=${BENCH_NET2_SUBNET:-172.31.254.0/24}
    PEER1_IP="${NET_SUBNET%.*}.30"; PEER2_IP="${NET2_SUBNET%.*}.31"
    SUT2_IP="${NET2_SUBNET%.*}.20"
    NH1=10.99.0.1; NH2=10.99.1.1
    export LC_ALL=C
    # split the feed: odd-index prefixes via NH1, even via NH2
    awk -v n="$LIMIT" -v nh1="$NH1" -v nh2="$NH2" \
        'NR <= n && /next-hop/ { sub(/next-hop [0-9.]*/, "next-hop " ((NR % 2 == 1) ? nh1 : nh2)) } NR <= n' \
        "$ANN_CP" > "$OUT_DIR/announce-split.txt"
    ANN_SPLIT=$(cd "$OUT_DIR" && pwd)/announce-split.txt
    SUT=x4p-sut-$TS; INJ=x4p-inj-$TS; PEER=x4p-p1-$TS; PEER2=x4p-p2-$TS
    trap 'docker rm -f "$SUT" "$INJ" "$PEER" "$PEER2" >/dev/null 2>&1 || true' EXIT
    note "=== e4partial mode=$MODE limit=$LIMIT runs=$RUNS (half $NH1 on $NET_NAME, half $NH2 on $NET2_NAME)"
    docker network inspect "$NET2_NAME" >/dev/null 2>&1 \
        || docker network create --subnet "$NET2_SUBNET" "$NET2_NAME"
    new_sut "$SUT"
    # two p2p adjacencies need two links (a shared segment with three
    # routers stalls LSDB exchange for one peer in every speaker
    # combination tried — the finding that shaped this shape)
    docker network connect --ip "$SUT2_IP" "$NET2_NAME" "$SUT"
    start_rousterd "$SUT"
    if [ "$MODE" = mixed ]; then
        docker exec "$SUT" sh -c "printf '%s\n' \
            'frr version 10.2' 'frr defaults traditional' 'hostname x4p' \
            'router bgp $SUT_AS' \
            ' no bgp network import-check' ' no bgp ebgp-requires-policy' \
            ' neighbor $INJ_IP remote-as $INJ_AS' \
            ' neighbor $INJ_IP ebgp-multihop 2' \
            ' neighbor $INJ_IP timers 30 $HOLD' \
            ' address-family ipv4 unicast' '  exit-address-family' 'line vty' \
            > /etc/frr/bgpd.conf"
        docker exec "$SUT" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/bgpd.log --log-level info"
        wait_up "$SUT" "frr bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
    else
        start_rouster_bgpd "$SUT"
    fi
    if [ "$MODE" = frrspf ]; then
        # FRR ospfd as the SUT's OSPF speaker (only the OSPF speaker
        # swaps; the core and the bgpd stay rouster's)
        docker exec "$SUT" sh -c "printf '%s\n' \
            'frr version 10.2' 'frr defaults traditional' 'hostname x4p' \
            'interface eth0' ' ip ospf network point-to-point' \
            ' ip ospf hello-interval 2' ' ip ospf dead-interval 8' \
            'interface eth1' ' ip ospf network point-to-point' \
            ' ip ospf hello-interval 2' ' ip ospf dead-interval 8' \
            'router ospf' ' ospf router-id 1.1.1.1' \
            ' network $NET_SUBNET area 0.0.0.0' \
            ' network $NET2_SUBNET area 0.0.0.0' \
            ' timers throttle spf 0 50 100' \
            'line vty' > /etc/frr/ospfd.conf"
        docker exec "$SUT" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/ospfd.log --log-level info"
        wait_up "$SUT" "frr ospfd vty" 30 "test -S /var/run/frr/ospfd.vty"
    else
        docker cp "$BIN_DIR/rouster-ospfd" "$SUT:/usr/local/bin/rouster-ospfd"
        docker exec "$SUT" sh -c "printf '%s\n' \
            'zapi socket /var/run/frr/zserv.api' \
            'router ospf' ' router-id 1.1.1.1' \
            ' area 0.0.0.0' \
            '  interface eth0' \
            '   network-type point-to-point' \
            '   hello-interval 2' '   dead-interval 8' \
            '  interface eth1' \
            '   network-type point-to-point' \
            '   hello-interval 2' '   dead-interval 8' \
            > /etc/rouster-ospfd.conf"
        docker exec -d "$SUT" sh -c "rouster-ospfd --config /etc/rouster-ospfd.conf > /var/log/rouster-ospfd.log 2>&1"
        wait_up "$SUT" "rouster ospfd up" 20 "pidof rouster-ospfd"
    fi
    # two OSPF peers, each on its own segment, each advertising its
    # own dummy /24 — with BOTH the transit AND the lo network
    # statements (the round-5 rebuild dropped the transit one, which
    # is why no hello ever left eth0)
    for PSPEC in "$PEER $PEER1_IP $NH1 2.2.2.2 $NET_NAME $NET_SUBNET" "$PEER2 $PEER2_IP $NH2 3.3.3.3 $NET2_NAME $NET2_SUBNET"; do
        set -- $PSPEC
        PNAME=$1; PIP=$2; PNH=$3; PRID=$4; PSEG=$5; PSEGS=$6
        docker run -d --name "$PNAME" --network "$PSEG" --ip "$PIP" \
            --cpuset-cpus "$INJ_CPUS" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
            --entrypoint sleep "$IMAGE" infinity >/dev/null
        docker exec "$PNAME" sh -c "ip addr add $PNH/24 dev lo 2>/dev/null || true; ip link set lo up"
        docker exec "$PNAME" sh -c "/usr/lib/frr/zebra -d --log file:$FRRLOG/pz-$PNAME.log --log-level info"
        wait_up "$PNAME" "$PNAME zebra" 30 "test -S /var/run/frr/zebra.vty"
        docker exec "$PNAME" sh -c "printf '%s\n' \
            'frr version 10.2' 'frr defaults traditional' 'hostname $PNAME' \
            'interface eth0' ' ip ospf network point-to-point' \
            ' ip ospf hello-interval 2' \
            ' ip ospf dead-interval 8' \
            'router ospf' ' ospf router-id $PRID' \
            ' network $PSEGS area 0.0.0.0' \
            ' network ${PNH%.*}.0/24 area 0.0.0.0' \
            ' timers throttle spf 0 50 100' \
            'line vty' > /etc/frr/ospfd.conf"
        docker exec "$PNAME" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/po-$PNAME.log --log-level info"
        wait_up "$PNAME" "$PNAME ospfd" 30 "test -S /var/run/frr/ospfd.vty"
    done
    # adjacency gate — `case` glob, NOT `[ = Full ]`: a p2p neighbor
    # renders as Full/- and the POSIX test has no patterns
    ADJ1=$(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | awk '/^[0-9]+\./ {print $3; exit}')
    for _ in $(seq 1 60); do
        case "$ADJ1" in Full*) break ;; esac
        sleep 2
        ADJ1=$(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | awk '/^[0-9]+\./ {print $3; exit}')
    done
    ADJ2=$(docker exec "$PEER2" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | awk '/^[0-9]+\./ {print $3; exit}')
    for _ in $(seq 1 60); do
        case "$ADJ2" in Full*) break ;; esac
        sleep 2
        ADJ2=$(docker exec "$PEER2" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | awk '/^[0-9]+\./ {print $3; exit}')
    done
    note "adjacency peer1=$ADJ1 peer2=$ADJ2"
    case "${ADJ1}${ADJ2}" in
        Full*Full*) : ;;
        *)
            note "peer1-neighbors: $(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | tr '\n' '|')"
            note "peer2-neighbors: $(docker exec "$PEER2" sh -c "vtysh -c 'show ip ospf neighbor'" 2>/dev/null | tr '\n' '|')"
            note "peer1-ospf-if: $(docker exec "$PEER" sh -c "vtysh -c 'show ip ospf interface eth0'" 2>/dev/null | sed -n '1,4p' | tr '\n' '|')"
            docker exec "$PEER" sh -c "cat /tmp/frrrun/po-$PEER.log 2>/dev/null" > "$OUT_DIR/peer1-ospfd.log" 2>/dev/null || true
            docker exec "$PEER2" sh -c "cat /tmp/frrrun/po-$PEER2.log 2>/dev/null" > "$OUT_DIR/peer2-ospfd.log" 2>/dev/null || true
            docker exec "$SUT" sh -c "cat /var/log/rouster-ospfd.log 2>/dev/null" > "$OUT_DIR/sut-ospfd.log" 2>/dev/null || true
            docker exec "$SUT" sh -c "cat /tmp/frrrun/ospfd.log 2>/dev/null" >> "$OUT_DIR/sut-ospfd.log" 2>/dev/null || true
            docker exec "$SUT" sh -c "ip addr show" > "$OUT_DIR/sut-addr.txt" 2>/dev/null || true
            fail "e4partial: adjacency incomplete ($ADJ1/$ADJ2)"; exit 1 ;;
    esac
    sleep 8   # Full -> /32 installs on the SPF pacing constant (~5 s)
    docker exec "$SUT" sh -c "ip route show proto ospf" > "$OUT_DIR/ospf-routes.txt" 2>/dev/null || true
    note "ospf proto-ospf routes: $(grep -c . "$OUT_DIR/ospf-routes.txt" || true) — $(tr '\n' ';' < "$OUT_DIR/ospf-routes.txt")"
    # the BGP injector announcing the split feed (odd lines NH1, even NH2)
    docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
        --cpuset-cpus "$INJ_CPUS" -v "$ANN_SPLIT":/feed.announce:ro \
        --entrypoint sleep ${BENCH_E2_INJ_IMAGE:-bench-flap-runner:local} infinity >/dev/null
    docker cp scripts/bench-flap.py "$INJ:/bench-flap.py"
    docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
    docker exec -d "$INJ" sh -c "python3 /bench-flap.py --peer $SUT_IP:179 \
        --local-as $INJ_AS --peer-as $SUT_AS --router-id $INJ_IP \
        --announce /feed.announce --limit $LIMIT --flap-every 999999 \
        --rounds 0 --hold $HOLD --steady-wait 5 --linger $((RUNS * 800 + 400)) > /var/log/flap-run.txt 2>&1"
    # per-set readouts. The kernel carries the RESOLVED programming
    # form (rib.rs: gateway hops rewritten through the IGP route), so
    # the per-set discriminator is the SEGMENT GATEWAY (peer address),
    # 1:1 with the announced recursive nexthop (NH1/NH2). All sampling
    # runs INSIDE the SUT (the 1 Hz poller writes /dualseg.csv; host
    # gates read its tail — a file read, never a busy-netns query)
    via_count() { docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null | grep -c 'via $1'" || true; }
    set1_dump() { docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null | grep 'via $PEER1_IP' || true" | LC_ALL=C sort; }
    set2_dump() { docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null | grep 'via $PEER2_IP' || true" | LC_ALL=C sort; }
    dup_count() { docker exec "$SUT" sh -c "ip route show proto 186 2>/dev/null" | LC_ALL=C sort | uniq -d | grep -c . || true; }
    seg_tail() { docker exec "$SUT" sh -c "tail -1 /dualseg.csv" 2>/dev/null; }
    docker exec -d "$SUT" sh -c "
        : > /dualseg.csv
        end=\$(( \$(date +%s) + $((RUNS * 500 + 600)) ))
        while :; do
            t=\$(ip route show proto 186 2>/dev/null | grep -c .)
            v1=\$(ip route show proto 186 2>/dev/null | grep -c 'via $PEER1_IP')
            v2=\$(ip route show proto 186 2>/dev/null | grep -c 'via $PEER2_IP')
            o=\$(ip route show proto ospf 2>/dev/null | grep -c .)
            echo \"\$(date +%s.%N) \$t \$v1 \$v2 \$o\" >> /dualseg.csv
            [ \"\$(date +%s)\" -gt \"\$end\" ] && break
            sleep 1
        done"
    for _ in $(seq 1 240); do
        c=$(kern_count "$SUT"); [ "$c" -ge $((LIMIT - 20)) ] 2>/dev/null && break; sleep 1
    done
    VIA1_B=$(via_count "$PEER1_IP"); VIA2_B=$(via_count "$PEER2_IP"); TOTAL_B=$(kern_count "$SUT")
    note "baseline: total=$TOTAL_B seg1(via $PEER1_IP, announced $NH1)=$VIA1_B seg2(via $PEER2_IP, announced $NH2)=$VIA2_B (expect ~$((LIMIT/2)) each)"
    if [ "$VIA1_B" -lt $((LIMIT / 2 - 20)) ] 2>/dev/null || [ "$VIA2_B" -lt $((LIMIT / 2 - 20)) ] 2>/dev/null; then
        docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary' 2>&1 | tail -3; ip route show proto ospf" > "$OUT_DIR/diag-$MODE.txt" 2>/dev/null || true
        docker exec "$INJ" sh -c "cat /var/log/flap-run.txt 2>/dev/null | head -8" > "$OUT_DIR/flap-head-$MODE.txt" 2>/dev/null || true
        fail "e4partial $MODE: baseline per-set counts short ($VIA1_B/$VIA2_B of ~$((LIMIT/2)))"; exit 1
    fi
    # the event, RUNS times: kill peer-1 ospfd -> only the NH1 set
    # withdraws; restart it -> exact prior counts return
    R_ALL_PASS=1
    for R in $(seq 1 "$RUNS"); do
        VIA1_PRE=$(via_count "$PEER1_IP"); VIA2_PRE=$(via_count "$PEER2_IP"); DUP_PRE=$(dup_count)
        set1_dump > "$OUT_DIR/run$R-pre-set1.txt"; set2_dump > "$OUT_DIR/run$R-pre-set2.txt"
        docker exec "$SUT" sh -c "pkill -f 'ping -i 0.2' 2>/dev/null" >/dev/null 2>&1 || true
        docker exec -d "$SUT" sh -c "ping -i 0.2 -c 2500 $NH1 > /probe1-r$R.txt 2>&1"
        docker exec -d "$SUT" sh -c "ping -i 0.2 -c 2500 $NH2 > /probe2-r$R.txt 2>&1"
        TKILL=$(date +%s.%N)
        docker exec "$PEER" sh -c 'kill -9 "$(pidof ospfd)"'
        # withdraw gate: NH1 set -> 0 within 120 s (frozen readout),
        # gated on the in-SUT sampler, not a host-side netns poll
        WD_OK=0
        for _ in $(seq 1 125); do
            v1=$(seg_tail | awk '{print $3}')
            [ "$v1" = 0 ] 2>/dev/null && { WD_OK=1; break; }; sleep 1
        done
        TW=$(date +%s.%N)
        sleep 3
        VIA1_MID=$(via_count "$PEER1_IP"); VIA2_MID=$(via_count "$PEER2_IP"); DUP_MID=$(dup_count)
        set2_dump > "$OUT_DIR/run$R-mid-set2.txt"
        OSPF_MID=$(docker exec "$SUT" sh -c "ip route show proto ospf 2>/dev/null | grep -c ." || true)
        # restore: restart peer-1 ospfd from the same -f config
        TRST=$(date +%s.%N)
        docker exec "$PEER" sh -c "/usr/lib/frr/ospfd -d -f /etc/frr/ospfd.conf -z /var/run/frr/zserv.api --log file:$FRRLOG/po-$PEER-r$R.log --log-level info"
        RS_OK=0
        for _ in $(seq 1 240); do
            v1=$(seg_tail | awk '{print $3}'); v2=$(seg_tail | awk '{print $4}')
            if [ "$v1" = "$VIA1_PRE" ] 2>/dev/null && [ "$v2" = "$VIA2_PRE" ] 2>/dev/null; then RS_OK=1; break; fi
            sleep 1
        done
        TEND=$(date +%s.%N)
        sleep 5
        VIA1_POST=$(via_count "$PEER1_IP"); VIA2_POST=$(via_count "$PEER2_IP"); DUP_POST=$(dup_count); TOTAL_POST=$(kern_count "$SUT")
        set1_dump > "$OUT_DIR/run$R-post-set1.txt"; set2_dump > "$OUT_DIR/run$R-post-set2.txt"
        OSPF_POST=$(docker exec "$SUT" sh -c "ip route show proto ospf 2>/dev/null | grep -c ." || true)
        DIFF_PRE=$(comm -3 "$OUT_DIR/run$R-pre-set1.txt" "$OUT_DIR/run$R-post-set1.txt" | grep -c . || true)
        python3 - "$R" "$TKILL" "$TW" "$TRST" "$TEND" "$VIA1_PRE" "$VIA2_PRE" "$DUP_PRE" \
            "$VIA1_MID" "$VIA2_MID" "$DUP_MID" "$OSPF_MID" \
            "$VIA1_POST" "$VIA2_POST" "$DUP_POST" "$TOTAL_POST" "$OSPF_POST" "$TOTAL_B" \
            "$WD_OK" "$RS_OK" "$DIFF_PRE" >> "$OUT_DIR/notes.txt" <<'PYEOF'
import sys
(r, tk, tw, trst, tend, v1p, v2p, dp, v1m, v2m, dm, om,
 v1q, v2q, dq, tq, oq, tb, wd, rs, dif) = sys.argv[1:]
r = int(r); tk, tw, trst, tend = map(float, (tk, tw, trst, tend))
v1p, v2p, dp, v1m, v2m, dm, om, v1q, v2q, dq, tq, oq, tb = map(int,
    (v1p, v2p, dp, v1m, v2m, dm, om, v1q, v2q, dq, tq, oq, tb))
wd, rs, dif = int(wd), int(rs), int(dif)
persist = v2m * 100 >= v2p * 99
print(f"X-NOTE e4partial run{r}: kill @{tw-tk:.1f}s wd_ok={wd} "
      f"(via1 {v1p}->{v1m}, via2 {v2m}/{v2p} = {100.0*v2m/max(v2p,1):.2f}% persisted, "
      f"dups {dm}); restore ok={rs} @+{tend-trst:.1f}s "
      f"(via1 {v1q}=={v1p} {v1q==v1p}, via2 {v2q}=={v2p} {v2q==v2p}, "
      f"total {tq}/{tb}, dups {dq}, set1 diff-lines {dif}); "
      f"ospf-routes mid/post {om}/{oq}")
why = []
if not wd or tw - tk > 120: why.append(f"withdraw {'incomplete' if not wd else f'slow {tw-tk:.1f}s'}")
if not persist: why.append(f"healthy half disturbed {v2m}/{v2p}")
if not rs or v1q != v1p or v2q != v2p: why.append("restore not exact")
if dp or dm or dq: why.append(f"duplicates {dp}/{dm}/{dq}")
if why:
    print(f"X-FAIL e4partial run{r}: ISOLATION-PARTIAL — {'; '.join(why)}")
else:
    print(f"X-PASS e4partial run{r}: ISOLATION-PASS "
          f"(withdraw {tw-tk:.1f}s, persist {v2m}/{v2p}, restore exact {tend-trst:.1f}s, 0 dups)")
PYEOF
        if [ "$WD_OK" = 1 ] && [ "$RS_OK" = 1 ] \
            && [ "$VIA1_POST" = "$VIA1_PRE" ] && [ "$VIA2_POST" = "$VIA2_PRE" ] \
            && [ "$DUP_PRE" = 0 ] && [ "$DUP_MID" = 0 ] && [ "$DUP_POST" = 0 ] \
            && [ "$VIA2_MID" -ge $((VIA2_PRE * 99 / 100)) ] 2>/dev/null; then
            :
        else
            R_ALL_PASS=0
        fi
        docker exec "$SUT" sh -c "pkill -f 'ping -i 0.2' 2>/dev/null" >/dev/null 2>&1 || true
        sleep 2
        docker cp "$SUT:/probe1-r$R.txt" "$OUT_DIR/probe1-r$R.txt" 2>/dev/null || true
        docker cp "$SUT:/probe2-r$R.txt" "$OUT_DIR/probe2-r$R.txt" 2>/dev/null || true
    done
    docker exec "$SUT" sh -c "cat /dualseg.csv" > "$OUT_DIR/dualseg.csv" 2>/dev/null || true
    docker exec "$INJ" sh -c "cat /var/log/flap-run.txt" > "$OUT_DIR/flap.txt" 2>/dev/null || true
    docker exec "$PEER" sh -c "cat /tmp/frrrun/po-$PEER.log /tmp/frrrun/po-$PEER-r*.log 2>/dev/null" > "$OUT_DIR/peer1-ospfd.log" 2>/dev/null || true
    docker exec "$SUT" sh -c "cat /var/log/rouster-ospfd.log 2>/dev/null; cat /tmp/frrrun/ospfd.log 2>/dev/null" > "$OUT_DIR/sut-ospfd.log" 2>/dev/null || true
    docker cp "$SUT:/var/log/rousterd.log" "$OUT_DIR/rousterd.log" 2>/dev/null || true
    if [ "$R_ALL_PASS" = 1 ]; then
        pass "e4partial $MODE: ISOLATION-PASS on all $RUNS runs"
    else
        fail "e4partial $MODE: ISOLATION-PARTIAL on at least one run (numbers above)"
    fi
    ;;
*) echo "unknown cell $CELL" >&2; exit 1 ;;
esac
echo "bench-x: done — $OUT_DIR"
