#!/usr/bin/env bash
# bench-e3-sessions.sh — the E3 session-establishment scaling harness
# (docs/benchmarks.md §E3; S14-b PERF-X stream — the multi-core
# architecture claim put to a number).
#
# Shape (the pre-registered E3 entry + the 2026-10-16 protocol
# addendum): N mrt-replay injector containers (one per BGP session,
# one source IP each — mrt-replay does not bind --local-addr, so one
# container per session is the honest way to get N distinct peers),
# all connecting to ONE SUT "simultaneously": every fleet member
# spins until a common T0 (the containers share the VM clock), then
# execs mrt-replay with a small per-session table (--table prefixes;
# the protocol entry says a small table suffices — this measures
# session machinery, not table scale).
#
# Cells: N ∈ BENCH_E3_NS (default "10 50 100") × SUT cores ∈
# BENCH_E3_CORES (default "1 2 4"; SUT cpuset 4, 4-5, 4-7 — disjoint
# from the injector pins 0-3). Per cell: runs = 1 warmup + measured.
#
# Metrics (folded by bench-ex-summarize.py --e3): wall first-connect
# (min REPLAY-START) → all-N Established (max REPLAY-ESTABLISHED),
# sessions/s, establishment failures at the deadline, SUT-side
# Established cross-count, SUT daemon CPU.
#
#   scripts/bench-e3-sessions.sh rouster|frr <raw-mrt> [runs]
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: bench-e3-sessions.sh rouster|frr <raw-mrt> [runs]}
FEED_MRT=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
RUNS=${3:-6}
NS=${BENCH_E3_NS:-"10 50 100"}
CORESES=${BENCH_E3_CORES:-"1 2 4"}
TABLE=${BENCH_E3_TABLE:-100}
FLEET_TAG=${BENCH_E3_FLEET_TAG:-rouster-bench-mrt:local}
DEADLINE=${BENCH_E3_DEADLINE:-120}

SUT_AS=65000
INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
IMAGE=frr-testbed:10.2.2
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
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
OUT_DIR="target/bench-logs/e3-$TS"
mkdir -p "$OUT_DIR"
echo "bench-e3-sessions: mode=$MODE feed=$FEED_MRT ns=[$NS] cores=[$CORESES]"
echo "  table/session=$TABLE runs=$RUNS out=$OUT_DIR"

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=e3x-) >/dev/null 2>&1 || true

if [ "$MODE" = rouster ]; then
    if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
        rustup target add "$MUSL_TARGET"
    fi
    echo "==> building bgpd + mrt-replay ($MUSL_TARGET, release)"
    cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd
    cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
    cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd
    cargo build --release --target "$MUSL_TARGET" -p bgpd --bin mrt-replay
    # The fleet image (built once per session; binary baked in).
    if ! docker image inspect "$FLEET_TAG" >/dev/null 2>&1; then
        CTX=target/bench-ctx-mrt
        rm -rf "$CTX" && mkdir -p "$CTX"
        cp "target/$MUSL_TARGET/release/mrt-replay" "$CTX/mrt-replay"
        docker build -f docker/bench/Dockerfile.mrt-replay "$CTX" -t "$FLEET_TAG"
    fi
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

# SUT neighbor config for N peers at 172.31.255.101.. — written on
# the host, pushed in (both daemons take plain-text neighbor lists).
write_configs() { # n out-rouster out-frr
    local n=$1 our=$2 frrc=$3 i ip
    : > "$our"; : > "$frrc"
    printf '%s\n' 'zapi socket /run/rouster/zserv.api' >> "$our"
    printf '%s\n' "router bgp $SUT_AS" ' bgp router-id '"$SUT_IP" >> "$our"
    printf '%s\n' " hold-time $HOLD" >> "$our"
    for i in $(seq 1 "$n"); do
        ip=172.31.255.$((100 + i))
        printf '%s\n' " neighbor $ip remote-as $INJ_AS" " neighbor $ip passive" >> "$our"
    done
    printf '%s\n' 'frr version 10.2' 'frr defaults traditional' 'hostname bench-frr' \
        "router bgp $SUT_AS" ' no bgp network import-check' ' no bgp ebgp-requires-policy' >> "$frrc"
    for i in $(seq 1 "$n"); do
        ip=172.31.255.$((100 + i))
        printf '%s\n' " neighbor $ip remote-as $INJ_AS" " neighbor $ip timers 30 $HOLD" >> "$frrc"
    done
    printf '%s\n' ' address-family ipv4 unicast' '  exit-address-family' 'line vty' >> "$frrc"
}

for N in $NS; do
    for CORES in $CORESES; do
        case "$CORES" in
            1) SUT_CPUS=4 ;;
            2) SUT_CPUS=4-5 ;;
            4) SUT_CPUS=4-7 ;;
            *) SUT_CPUS=${BENCH_SUT_CPUS:-4-11} ;;
        esac
        CELL_DIR="$OUT_DIR/$MODE/n$N-c$CORES"
        mkdir -p "$CELL_DIR"
        write_configs "$N" "$CELL_DIR/rouster-bgp.conf" "$CELL_DIR/frr.conf"
        echo "sha256 frr.conf $(shasum -a 256 "$CELL_DIR/frr.conf" | awk '{print $1}')" >> "$OUT_DIR/PROTOCOL.txt"
        echo "sha256 rouster-bgp.conf $(shasum -a 256 "$CELL_DIR/rouster-bgp.conf" | awk '{print $1}')" >> "$OUT_DIR/PROTOCOL.txt"
        for run in $(seq 1 "$RUNS"); do
            RUN_DIR="$CELL_DIR/run-$run"
            mkdir -p "$RUN_DIR/fleet"
            RUN_DIR_ABS=$(cd "$RUN_DIR" && pwd)
            SUT=e3x-sut-$TS-$N-$CORES-$run
            trap 'docker rm -f $(docker ps -aq --filter name=e3x-) >/dev/null 2>&1 || true' EXIT
            docker rm -f $(docker ps -aq --filter name=e3x-) >/dev/null 2>&1 || true
            echo "==> n=$N cores=$CORES run $run/$RUNS (sut cpus $SUT_CPUS)"

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
                docker cp "$CELL_DIR/frr.conf" "$SUT:/etc/frr/frr.conf"
                applied=0
                for _ in $(seq 1 10); do
                    docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
                    sleep 2
                    if [ "$(docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -c '172\.31\.255\.')" -ge "$N" ]; then
                        applied=1; break
                    fi
                done
                [ "$applied" = 1 ] || { echo "FAIL: FRR $N-neighbor config never applied" >&2; exit 1; }
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
                docker cp "$CELL_DIR/rouster-bgp.conf" "$SUT:/etc/rouster-bgp.conf"
                docker exec "$SUT" sh -c "rouster-bgpd --validate-config /etc/rouster-bgp.conf"
                docker exec -d "$SUT" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > /var/log/rouster-bgpd.log 2>&1"
                wait_up "$SUT" "rouster bgpd listening" 15 "grep -q 'bgpd: listening' /var/log/rouster-bgpd.log"
            fi

            # --- the fleet: N pinned injector containers, staged idle ----
            # Each container's MAIN command is the waiter: it polls the
            # shared /fleet/GO file (the harness writes the release epoch
            # once staging is COMPLETE), coarse-sleeps to release-1s and
            # spins on the second flip — so the release spread is the
            # clock, not a docker-exec launch loop (the first grid's
            # N>=50 walls measured that loop, 2.5-11.6 s of injector
            # skew; diagnosed from start_spread==wall and fixed here).
            rm -f "$RUN_DIR/fleet/GO"
            for i in $(seq 1 "$N"); do
                IP=172.31.255.$((100 + i))
                docker run -d --name "e3x-inj-$i" --network "$NET_NAME" --ip "$IP" \
                    --cpuset-cpus "$INJ_CPUS" \
                    -v "$FEED_MRT":/feed.mrt:ro \
                    -v "$RUN_DIR_ABS/fleet":/fleet \
                    -e SUT_IP=$SUT_IP -e OWN_IP=$IP -e INJ_AS=$INJ_AS \
                    -e SUT_AS=$SUT_AS -e TABLE=$TABLE -e HOLD=$HOLD -e IDX=$i \
                    --entrypoint sh "$FLEET_TAG" -c '
                    while [ ! -s /fleet/GO ]; do sleep 0.1; done
                    T0=$(cat /fleet/GO)
                    while [ "$(date +%s)" -lt $((T0 - 1)) ]; do sleep 0.1; done
                    while [ "$(date +%s)" -lt "$T0" ]; do :; done
                    exec mrt-replay --peer $SUT_IP:179 --local-addr $OWN_IP \
                        --local-as $INJ_AS --peer-as $SUT_AS --router-id $OWN_IP \
                        --mrt /feed.mrt --prepend-as $INJ_AS --next-hop $OWN_IP \
                        --limit $TABLE --rate 0 --hold $HOLD --linger 60 \
                        > /fleet/inj-$IDX.txt 2>&1'
            done
            # fleet staged and all waiters armed: release in 3 s
            T0=$(( $(date +%s) + 3 ))
            echo "$T0" > "$RUN_DIR/fleet/GO"
            echo "$T0" > "$RUN_DIR/t0.txt"

            # --- poller: fleet Established count + SUT cross-count -------
            python3 - "$RUN_DIR" "$N" "$DEADLINE" "$MODE" "$SUT" > "$RUN_DIR/poller.log" 2>&1 <<'EOF'
import glob, re, subprocess, sys, time
run_dir, n, deadline, mode, sut = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
t0 = time.time()
print("t_host,established,sut_established,bgpd_jiffies,zebra_jiffies,bgpd_rss_kb,zebra_rss_kb", flush=True)
def sh(c, body):
    try:
        return subprocess.run(["docker", "exec", c, "sh", "-c", body],
                              capture_output=True, text=True, timeout=15).stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
while time.time() - t0 < deadline:
    now = f"{time.time():.6f}"
    # fleet count from the host-visible volume (no container needed)
    est = 0
    for f in glob.glob(f"{run_dir}/fleet/inj-*.txt"):
        try:
            if "REPLAY-ESTABLISHED" in open(f, errors="replace").read():
                est += 1
        except OSError:
            pass
    if mode == "rouster":
        sut_est = sh(sut, "grep -c 'session Established' /var/log/rouster-bgpd.log 2>/dev/null")
        p = sh(sut, "for n_ in rouster-bgpd rousterd; do p=$(pidof $n_ | awk \"{print \\$1}\"); [ -n \"$p\" ] || continue; echo $n_ $(awk \"{print \\$14, \\$15}\" /proc/$p/stat) $(awk \"/VmRSS/{print \\$2}\" /proc/$p/status); done")
    else:
        sut_est = sh(sut, "vtysh -c 'show bgp ipv4 unicast summary json' 2>/dev/null | grep -oE '\"(peerState|state)\": *\"[^\"]*\"' | grep -c Established")
        p = sh(sut, "for n_ in bgpd zebra; do p=$(pidof $n_ | awk \"{print \\$1}\"); [ -n \"$p\" ] || continue; echo $n_ $(awk \"{print \\$14, \\$15}\" /proc/$p/stat) $(awk \"/VmRSS/{print \\$2}\" /proc/$p/status); done")
    j = {"rouster-bgpd": "", "rousterd": "", "bgpd": "", "zebra": ""}
    rss = dict(j)
    for line in p.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[0] in j:
            j[parts[0]] = str(int(parts[1]) + int(parts[2]))
            rss[parts[0]] = parts[3]
    speaker = "rouster-bgpd" if mode == "rouster" else "bgpd"
    core = "rousterd" if mode == "rouster" else "zebra"
    print(f"{now},{est},{sut_est or 0},{j[speaker]},{j[core]},{rss[speaker]},{rss[core]}", flush=True)
    if est >= n:
        time.sleep(2)  # settle: trailing sessions + CPU tail
        now = f"{time.time():.6f}"
        print(f"{now},{est},{sut_est or 0},{j[speaker]},{j[core]},{rss[speaker]},{rss[core]}", flush=True)
        print(f"POLL-COMPLETE", flush=True)
        break
    time.sleep(1)
else:
    print("POLL-DEADLINE", flush=True)
EOF

            # --- capture --------------------------------------------------
            for f in bgpd zebra mgmtd; do
                docker cp "$SUT:/tmp/$f.log" "$RUN_DIR/$f.log" 2>/dev/null || true
            done
            docker cp "$SUT:/var/log/rouster-bgpd.log" "$RUN_DIR/sut-bgpd.log" 2>/dev/null || true
            docker cp "$SUT:/var/log/rousterd.log" "$RUN_DIR/rousterd.log" 2>/dev/null || true
            if [ "$MODE" = frr ]; then
                docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary'" \
                    > "$RUN_DIR/final-vtysh.txt" 2>&1 || true
            else
                docker exec "$SUT" sh -c "cat /proc/\$(pidof rouster-bgpd)/stat /proc/\$(pidof rousterd)/stat" \
                    > "$RUN_DIR/final-proc-stat.txt" 2>/dev/null || true
                docker cp "$SUT:/run/rouster/rousterd.status" "$RUN_DIR/final-status.txt" 2>/dev/null || true
            fi
            docker exec "$SUT" getconf CLK_TCK > "$RUN_DIR/clk-tck.txt" 2>/dev/null || echo 100 > "$RUN_DIR/clk-tck.txt"
            H=$(date +%s.%N); V=$(docker exec "$SUT" date +%s.%N); H2=$(date +%s.%N)
            python3 - "$H" "$V" "$H2" >"$RUN_DIR/clock-offset.txt" <<'PYEOF'
import sys
h1, v, h2 = (float(x) for x in sys.argv[1:4])
print(f"host_minus_vm={(h1+h2)/2-v:.6f} sampling_span={h2-h1:.6f}")
PYEOF
            docker rm -f $(docker ps -aq --filter name=e3x-) >/dev/null 2>&1 || true
            echo "    run $run artifacts: $RUN_DIR (established=$(tail -2 "$RUN_DIR/poller.log" | head -1 | cut -d, -f2))"
        done
        CLK=$(head -1 "$CELL_DIR/run-1/clk-tck.txt" 2>/dev/null || echo 100)
        python3 scripts/bench-ex-summarize.py --e3 --mode "$MODE" \
            --out-dir "$CELL_DIR" --sessions "$N" --cores "$CORES" --clk-tck "$CLK"
    done
done
echo "bench-e3-sessions: done — $OUT_DIR"
