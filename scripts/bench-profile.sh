#!/usr/bin/env bash
# bench-profile.sh — the P0-c profiling rig (docs/benchmarks.md §R,
# 2026-10-16 entry): a documented, scriptable profile path for both
# daemons on the bench rig.
#
# CHOICE (disclosed, no-deps-first — PERF-P0's fence permits no new
# dependencies and no workspace Rust changes): /proc/<pid>/smaps
# rollups sampled around a pinned, reproducible N-prefix ingest. The
# smaps series gives the RSS composition per mapping (heap, stack,
# anonymous arenas, file-backed), which names the memory consumer
# without an allocator profile. CPU-side naming stays with the E7
# criterion micros until an owner-approved profiler lands.
#
# Escalated alternatives, NOT taken (owner decisions):
#   - a SIGQUIT dump-allocations census behind a feature flag (needs
#     a crates/ change — outside this stream's file fence); bgpd's
#     variant has since landed separately as the feature-gated
#     mem-census with its own receipt runner (PERF-M1 @7307053,
#     scripts/test-bgp-mem-slice.sh) — use that for bgpd internals,
#     this rig for rousterd and the FRR side;
#   - pprof-style sampling behind --features perf-flamegraph (needs
#     a profiler dev-dependency).
#
# Protocol — a before/after artifact pair:
#   1. Pin the feed (route-views MRT), the limit (default: the
#      100k slice), the image, and the binary build.
#   2. Run this script BEFORE an optimization change; keep the
#      produced target/bench-logs/profile-<ts>/ directory.
#   3. Apply the change, rebuild, run it again.
#   4. Compare rollup.tsv (per-sample RSS totals + top mapping) and
#      the per-mark smaps/ directories between the two runs. The
#      PROTOCOL.txt in each directory records what produced it.
#
# Usage:
#   scripts/bench-profile.sh rouster|frr <raw-mrt> [limit] [sample-interval-s]
#
# Env knobs (defaults reproduce the E1 rig exactly): BENCH_NET_NAME,
# BENCH_NET_SUBNET, BENCH_SUT_IP, BENCH_INJ_IP, BENCH_SUT_CPUS,
# BENCH_INJ_CPUS, BENCH_HOLD, BENCH_PROFILE_TIMEOUT.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

MODE=${1:?usage: bench-profile.sh rouster|frr <raw-mrt> [limit] [interval]}
FEED_MRT=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
LIMIT=${3:-100000}
INTERVAL=${4:-1}

SUT_AS=65000
INJ_AS=65412
NET_NAME=${BENCH_NET_NAME:-bench-net}
NET_SUBNET=${BENCH_NET_SUBNET:-172.31.255.0/24}
SUT_IP=${BENCH_SUT_IP:-172.31.255.20}
INJ_IP=${BENCH_INJ_IP:-172.31.255.10}
IMAGE=frr-testbed:10.2.2
SUT_CPUS=${BENCH_SUT_CPUS:-4-11}
INJ_CPUS=${BENCH_INJ_CPUS:-0-3}
HOLD=${BENCH_HOLD:-90}
TIMEOUT=${BENCH_PROFILE_TIMEOUT:-600}

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *)             echo "unknown arch $(uname -m)" >&2; exit 1 ;;
esac

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT_DIR="target/bench-logs/profile-$TS"
mkdir -p "$OUT_DIR"
echo "bench-profile: mode=$MODE feed=$FEED_MRT limit=$LIMIT interval=${INTERVAL}s out=$OUT_DIR"

# The daemons this mode profiles (pidof names inside the SUT).
if [ "$MODE" = frr ]; then DAEMONS="bgpd zebra"; else DAEMONS="rouster-bgpd rousterd"; fi

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker network inspect "$NET_NAME" >/dev/null 2>&1 \
    || docker network create --subnet "$NET_SUBNET" "$NET_NAME"
docker rm -f $(docker ps -aq --filter name=p0p-) >/dev/null 2>&1 || true

if [ "$MODE" != frr ]; then
    if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
        rustup target add "$MUSL_TARGET"
    fi
    echo "==> building rousterd + bgpd + mrt-replay ($MUSL_TARGET, release)"
    cargo build --release --target "$MUSL_TARGET" -p rousterd --bin rousterd
    cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl
    cargo build --release --target "$MUSL_TARGET" -p bgpd --bin bgpd
    cargo build --release --target "$MUSL_TARGET" -p bgpd --bin mrt-replay
fi

SUT=p0p-sut-$TS
INJ=p0p-inj-$TS
trap 'docker rm -f "$SUT" "$INJ" >/dev/null 2>&1 || true' EXIT

wait_up() { # container desc attempts cmd
    for _ in $(seq 1 "$3"); do
        docker exec "$1" sh -c "$4" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "FAIL: $2 (waited ${3}s)" >&2
    return 1
}

if [ "$MODE" = frr ]; then
    docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" \
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
        " neighbor $INJ_IP remote-as $INJ_AS" \
        " neighbor $INJ_IP timers 30 $HOLD" \
        ' address-family ipv4 unicast' \
        '  exit-address-family' \
        'line vty' \
        > /etc/frr/frr.conf"
    for _ in $(seq 1 10); do
        docker exec "$SUT" vtysh -b >/dev/null 2>&1 || true
        sleep 2
        if docker exec "$SUT" sh -c "vtysh -c 'show bgp summary' 2>/dev/null" | grep -q "$INJ_IP"; then
            break
        fi
    done
    wait_up "$SUT" "frr bgpd bound :179" 30 "grep -qi '00B3' /proc/net/tcp"
else
    docker run -d --name "$SUT" --network "$NET_NAME" --ip "$SUT_IP" \
        --cpuset-cpus "$SUT_CPUS" \
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

# injector (identical shape to bench-e1-ingest)
docker run -d --name "$INJ" --network "$NET_NAME" --ip "$INJ_IP" \
    --cpuset-cpus "$INJ_CPUS" \
    -v "$FEED_MRT":/feed.mrt:ro \
    --entrypoint sleep alpine:3.20 infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/mrt-replay" "$INJ:/usr/local/bin/mrt-replay"
INJ_ARGS="--peer $SUT_IP:179 --local-addr $INJ_IP --local-as $INJ_AS \
    --peer-as $SUT_AS --router-id $INJ_IP --mrt /feed.mrt \
    --prepend-as $INJ_AS --next-hop $INJ_IP --limit $LIMIT \
    --rate 0 --hold $HOLD"

docker exec "$SUT" ping -c1 -W2 "$INJ_IP" >/dev/null 2>&1 || true
docker exec "$INJ" ping -c1 -W2 "$SUT_IP" >/dev/null 2>&1 || true

# --- PROTOCOL.txt: what produced these artifacts ----------------------
{
    echo "bench-profile.sh protocol record"
    echo "date_utc:        $TS"
    echo "mode:            $MODE"
    echo "repo_head:       $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "image:           $IMAGE"
    echo "feed:            $FEED_MRT"
    echo "feed_sha256:     $(shasum -a 256 "$FEED_MRT" | awk '{print $1}')"
    echo "limit:           $LIMIT"
    echo "sample_interval: ${INTERVAL}s"
    echo "sut_cpus:        $SUT_CPUS   inj_cpus: $INJ_CPUS"
    echo "net:             $NET_NAME $NET_SUBNET sut=$SUT_IP inj=$INJ_IP"
    echo "hold:            $HOLD   injector: unpaced (rate 0)"
    echo "kernel:          $(docker exec "$SUT" uname -r)"
    echo "clk_tck:         $(docker exec "$SUT" getconf CLK_TCK 2>/dev/null || echo 100)"
    if [ "$MODE" != frr ]; then
        for b in rousterd rouster-bgpd; do
            h=$(docker exec "$SUT" sha256sum "/usr/local/bin/$b" 2>/dev/null | awk '{print $1}')
            echo "sha256 $b: ${h:-unavailable}"
        done
        h=$(docker exec "$INJ" sha256sum /usr/local/bin/mrt-replay 2>/dev/null | awk '{print $1}')
        echo "sha256 mrt-replay (inj): ${h:-unavailable}"
    fi
    echo "replay_cmd:      mrt-replay $INJ_ARGS"
} > "$OUT_DIR/PROTOCOL.txt"

# --- the sampler -------------------------------------------------------
# One sample = a numbered directory under samples/ with, per daemon:
# status (VmPeak/VmSize/VmHWM/VmRSS/Threads), CPU jiffies, and the
# full smaps plus a per-mapping Rss rollup computed on the host.

sample() { # seq label
    local seq=$1 label=$2 d p dir
    mkdir -p "$OUT_DIR/samples/$seq-$label"
    echo "$(date +%s.%N) $seq $label" >> "$OUT_DIR/samples/index.txt"
    for d in $DAEMONS; do
        p=$(docker exec "$SUT" pidof "$d" | awk '{print $1}')
        [ -n "$p" ] || continue
        dir="$OUT_DIR/samples/$seq-$label/$d"
        mkdir -p "$dir"
        docker exec "$SUT" sh -c \
            "grep -E '^(VmPeak|VmSize|VmHWM|VmRSS|Threads):' /proc/$p/status" \
            > "$dir/status.txt" 2>/dev/null || true
        docker exec "$SUT" sh -c "awk '{print \$14, \$15}' /proc/$p/stat" \
            > "$dir/stat.txt" 2>/dev/null || true
        docker exec "$SUT" cat "/proc/$p/smaps" > "$dir/smaps.txt" 2>/dev/null || true
        awk '
            /^[0-9a-f]+-[0-9a-f]+ / {
                name = (NF >= 6 ? $6 : "(anon)")
                next
            }
            /^Rss:/ { rss[name] += $2; total += $2 }
            /^Pss:/ { pss += $2 }
            END {
                for (n in rss)
                    if (rss[n] > 0)
                        printf "%d %s\n", rss[n], n
                printf "TOTAL_RSS_KB %d\n", total
                printf "TOTAL_PSS_KB %d\n", pss
            }' "$dir/smaps.txt" | sort -rn > "$dir/rollup.txt"
    done
    # the tsv index row for this sample
    for d in $DAEMONS; do
        f="$OUT_DIR/samples/$seq-$label/$d/rollup.txt"
        [ -f "$f" ] || continue
        rss=$(awk '/^TOTAL_RSS_KB/{print $2}' "$f")
        pss=$(awk '/^TOTAL_PSS_KB/{print $2}' "$f")
        top=$(grep -v TOTAL "$f" | head -1)
        topn=$(echo "$top" | awk '{print $2}')
        topk=$(echo "$top" | awk '{print $1}')
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
            "$seq" "$label" "$d" "${rss:-0}" "${pss:-0}" "${topn:--}" "${topk:-0}" \
            >> "$OUT_DIR/rollup.tsv"
    done
}

printf "seq\tlabel\tdaemon\trss_kb\tpss_kb\ttop_mapping\ttop_mapping_kb\n" \
    > "$OUT_DIR/rollup.tsv"

echo "==> sampling empty mark"
sample 000 empty

echo "==> launching injector"
T_LAUNCH=$(date +%s.%N)
docker exec -d "$INJ" sh -c "mrt-replay $INJ_ARGS > /var/log/replay.txt 2>&1"

# Sample loop: run until the SUT's main table reaches the target (or
# timeout), sampling every INTERVAL seconds. Same completion
# tolerance as bench-poll.py: a SUT may legitimately reject a couple
# of feed routes — target is LIMIT minus max(2, 0.5%).
NEED=$(( LIMIT - (LIMIT / 200 > 2 ? LIMIT / 200 : 2) ))
SEQ=0
T0=$(date +%s)
while :; do
    sleep "$INTERVAL"
    SEQ=$((SEQ + 1))
    if [ "$MODE" = frr ]; then
        out=$(docker exec "$SUT" sh -c \
            "vtysh -c 'show ip route summary' 2>/dev/null" \
            | awk '/^Totals/{print $2}')
        label="t${SEQ}"
    else
        out=$(docker exec "$SUT" sh -c \
            "cat /run/rouster/rousterd.status 2>/dev/null" \
            | awk '/^table 254/{print $6}')
        label="t${SEQ}"
    fi
    sample "$SEQ" "$label"
    if [ -n "$out" ] && [ "$out" -ge "$NEED" ] 2>/dev/null; then
        echo "==> table reached target ($out >= $NEED) at sample $SEQ"
        break
    fi
    if [ $(( $(date +%s) - T0 )) -gt "$TIMEOUT" ]; then
        echo "PROFILE-TIMEOUT after $TIMEOUT s (last count: ${out:-none})" >&2
        break
    fi
done

sleep 20   # settle: post-complete allocator state (madvise etc.)
echo "==> sampling final mark"
sample 999 final

# Post-run facts: the SUT's own view + kernel route count + logs.
if [ "$MODE" = frr ]; then
    docker exec "$SUT" sh -c "vtysh -c 'show bgp ipv4 unicast summary'; vtysh -c 'show ip route summary'" \
        > "$OUT_DIR/final-vtysh.txt" 2>&1 || true
    for f in bgpd zebra mgmtd; do
        docker cp "$SUT:/tmp/$f.log" "$OUT_DIR/$f.log" 2>/dev/null || true
    done
else
    docker cp "$SUT:/run/rouster/rousterd.status" "$OUT_DIR/final-status.txt" 2>/dev/null || true
    docker cp "$SUT:/var/log/rousterd.log" "$OUT_DIR/rousterd.log" 2>/dev/null || true
    docker cp "$SUT:/var/log/rouster-bgpd.log" "$OUT_DIR/sut-bgpd.log" 2>/dev/null || true
fi
docker exec "$SUT" sh -c "ip route show proto bgp | wc -l" > "$OUT_DIR/kernel-bgp-routes.txt" 2>&1 || true
docker cp "$INJ:/var/log/replay.txt" "$OUT_DIR/injector.txt" 2>/dev/null || true

echo "bench-profile: done — $OUT_DIR"
echo "  compare before/after pairs with rollup.tsv and samples/*/"
