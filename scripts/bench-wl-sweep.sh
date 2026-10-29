#!/usr/bin/env bash
# bench-wl-sweep — the ToN-revision Part 5 P0 workload-diversity grid
# (plan 2026-10-29, prompt phase 3): one-dimensional sweeps over
# attribute uniqueness, candidates per prefix (ADD-PATH), and nexthop
# diversity, plus the pairwise stress cell and the controlled
# ablation pairs, at a fixed 100k scale, six runs per cell (one
# warmup + five measured), both systems per sweep where supported.
#
# Each cell is one bench-e1-ingest.sh invocation with the workload
# knobs (BENCH_WL_ARGS / BENCH_WL_COVER_ROUTE / BENCH_WL_ADDPATH /
# BENCH_SUT_ENV) set; the driver renames each OUT_DIR to the cell
# name, collects summary.json + the injector stats lines, and folds a
# grid JSON at the end. Baseline cells are NOT rerun: the natural-feed
# 100k receipts (§R 2026-10-19 onward) stand, per the do-not-rerun
# rule; the grid cites them by name.
#
# Usage (dgx-spark-1, lane free, from ~/rouster-bench):
#   BENCH_BIN_DIR=~/rouster-bench/bin-wl BENCH_INJECTOR_BIN=~/rouster-bench/bin-wl/mrt-replay \
#   bash scripts/bench-wl-sweep.sh <raw-mrt> [grid]
# Env:
#   WL_FEED_LIMIT   slice size (default 100000)
#   WL_RUNS         runs per cell (default 6 = 1 warmup + 5 measured)
#   WL_SIDES        "frr rouster" (default) or a subset
#   WL_CELLS        subset of cell names (default: all)
#   WL_SMOKE        1 (default) = 2k combined-shape smoke per side first
# The usual BENCH_* placement knobs (NET_NAME/SUBNET/IPs/CPUS) pass
# straight through to bench-e1-ingest.sh.
#
#   scripts/bench-wl-sweep.sh
set -euo pipefail
cd "$(dirname "$0")/.."

FEED_MRT=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
GRID_NAME=${2:-wl-grid}
LIMIT=${WL_FEED_LIMIT:-100000}
RUNS=${WL_RUNS:-6}
SIDES=${WL_SIDES:-"frr rouster"}
SMOKE=${WL_SMOKE:-1}
GRID_TS=$(date -u +%Y%m%dT%H%M%SZ)
GRID_DIR="target/bench-logs/${GRID_NAME}-${GRID_TS}"
mkdir -p "$GRID_DIR"
echo "bench-wl-sweep: feed=$FEED_MRT limit=$LIMIT runs=$RUNS sides=[$SIDES] grid=$GRID_DIR"

# cell spec: name|mode|WL_ARGS|WL_COVER|WL_ADDPATH|SUT_ENV  (|-separated;
# empty fields = unset). ablation cells are rouster-only (mode column
# drives the loop; SUT_ENV carries the lever).
CELLS="
a25|frr|--attr-unique 0.25|||
a50|frr|--attr-unique 0.50|||
a75|frr|--attr-unique 0.75|||
a100|frr|--attr-unique 1.00|||
a25|rouster|--attr-unique 0.25|||
a50|rouster|--attr-unique 0.50|||
a75|rouster|--attr-unique 0.75|||
a100|rouster|--attr-unique 1.00|||
c2|frr|--addpath 2|||
c4|frr|--addpath 4|||
c8|frr|--addpath 8|||
c2|rouster|--addpath 2||1|
c4|rouster|--addpath 4||1|
c8|rouster|--addpath 8||1|
n16|frr|--nexthop-pool 16|10.0.0.0/8||
n256|frr|--nexthop-pool 256|10.0.0.0/8||
n4096|frr|--nexthop-pool 4096|10.0.0.0/8||
n65535|frr|--nexthop-pool 65535|10.0.0.0/8||
n16|rouster|--nexthop-pool 16|10.0.0.0/8||
n256|rouster|--nexthop-pool 256|10.0.0.0/8||
n4096|rouster|--nexthop-pool 4096|10.0.0.0/8||
n65535|rouster|--nexthop-pool 65535|10.0.0.0/8||
stress|frr|--addpath 8 --attr-unique 1.00 --nexthop-pool 65535|10.0.0.0/8||
stress|rouster|--addpath 8 --attr-unique 1.00 --nexthop-pool 65535|10.0.0.0/8|1|
ab-ctl|rouster||||ROUSTER_ATTR_INTERN=1
ab-intern|rouster||||ROUSTER_ATTR_INTERN=0
ab-win64|rouster||||ROUSTER_NL_WINDOW=64
ab-win8|rouster||||ROUSTER_NL_WINDOW=8
ab-win1|rouster||||ROUSTER_NL_WINDOW=1
ab-fast1|rouster||||BGPD_FAST_ELECTION=1
"

# combined-shape smoke first: every knob exercised once at 2k per side
smoke_one() { # side
    local side=$1 out="$GRID_DIR/smoke-$side"
    echo "==> smoke $side (2k, all switches)"
    BENCH_WL_ARGS="--addpath 2 --attr-unique 0.5 --nexthop-pool 16" \
    BENCH_WL_COVER_ROUTE=10.0.0.0/8 \
    BENCH_WL_ADDPATH=$([ "$side" = rouster ] && echo 1 || echo "") \
    BENCH_OUT_NAME="$out" bash scripts/bench-e1-ingest.sh "$side" "$FEED_MRT" 1 2000 >/dev/null
}
if [ "$SMOKE" = 1 ]; then
    for s in $SIDES; do smoke_one "$s"; done
fi

run_cell() { # name mode wl_args cover addpath sut_env
    local name=$1 mode=$2 wl_args=$3 cover=$4 addpath=$5 sut_env=$6
    local out="$GRID_DIR/${name}-${mode}"
    echo "==> cell $name [$mode] args='$wl_args' env='$sut_env'"
    BENCH_WL_ARGS="$wl_args" \
    BENCH_WL_COVER_ROUTE="$cover" \
    BENCH_WL_ADDPATH="$addpath" \
    BENCH_SUT_ENV="$sut_env" \
    BENCH_OUT_NAME="$out" \
        bash scripts/bench-e1-ingest.sh "$mode" "$FEED_MRT" "$RUNS" "$LIMIT" >/dev/null
    # keep the injector stats lines with the grid
    for r in "$out"/run-*/injector.txt; do
        grep -h "REPLAY-ATTR-STATS\|REPLAY-NH-STATS" "$r" 2>/dev/null || true
    done | sort -u > "$out/injector-stats.txt" || true
}

echo "$CELLS" | grep -v '^$' | while IFS='|' read -r name mode wl cover ap env; do
    [ -z "$name" ] && continue
    if [ -n "${WL_CELLS:-}" ] && ! grep -qw "$name" <<<"${WL_CELLS}"; then
        # still allow per-(name,mode) targeting via "name:mode"
        grep -qw "$name:$mode" <<<"${WL_CELLS}" || continue
    fi
    if [ "$mode" = rouster ] || grep -qw "$mode" <<<"$SIDES"; then
        run_cell "$name" "$mode" "$wl" "$cover" "$ap" "$env"
    fi
done

# fold: one line per cell with the medians the sweeps report
python3 - "$GRID_DIR" <<'EOF'
import json, sys, glob, os, statistics as st
grid = sys.argv[1]
rows = []
for d in sorted(glob.glob(f"{grid}/*/")):
    name = os.path.basename(d.rstrip("/"))
    sj = os.path.join(d, "summary.json")
    if not os.path.exists(sj):
        continue
    try:
        runs = json.load(open(sj)).get("per_run", [])
    except Exception:
        continue
    meas = runs[1:] if len(runs) > 5 else runs
    def med(k):
        vs = [r[k] for r in meas if r.get(k) is not None]
        return round(st.median(vs), 3) if vs else None
    row = {
        "cell": name,
        "n": len(meas),
        "wall": med("wall_external_s"),
        "eor": med("wall_bgp_level_s"),
        "spk_cpu": med("sut_bgpd_cpu_s"),
        "core_cpu": med("sut_zebra_cpu_s"),
        "kernel_last": med("main_prefixes_last"),
        "overruns": sum(r.get("netlink_rcvbuf_overruns", 0) for r in meas),
    }
    # memory: B/pfx from final-empty RSS medians (the ledger convention)
    def bpf(k_final, k_empty):
        f, e = med(k_final), med(k_empty)
        if f and e is not None:
            return round((f - e) * 1024 / 100000, 1)
        return None
    row["spk_Bpfx"] = bpf("sut_bgpd_rss_final_kb", "sut_bgpd_rss_empty_kb")
    row["core_Bpfx"] = bpf("sut_zebra_rss_final_kb", "sut_zebra_rss_empty_kb")
    stats = os.path.join(d, "injector-stats.txt")
    if os.path.exists(stats):
        row["wire"] = open(stats).read().strip().replace("\n", "; ")
    rows.append(row)
json.dump(rows, open(f"{grid}/fold.json", "w"), indent=1)
print(json.dumps(rows, indent=1))
EOF
echo "bench-wl-sweep: done — $GRID_DIR/fold.json"
