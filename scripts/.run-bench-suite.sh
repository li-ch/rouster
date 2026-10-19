#!/bin/bash
# run-bench-suite.sh — the DGX follow-on suite, all on the single-
# cluster SUT pin (5-9): E4 both modes, E2 both sides, E3 grid both
# sides, E7 novel-attribute churn (rouster).
set -uo pipefail
cd "$HOME/rouster-bench"
export BENCH_BIN_DIR="$HOME/rouster-bench/bin"
export BENCH_SUT_CPUS="5-9"
export BENCH_INJ_CPUS="0-3"
export BENCH_SUT_RMEM=0
export BENCH_E4_OBS_CPUS="10-14"
export BENCH_E3_CPU1="5"
export BENCH_E3_CPU2="5-6"
export BENCH_E3_CPU4="5-8"
FEED="$HOME/rouster-bench/feed"
ANN="$HOME/rouster-bench/announce-100k.announce"

echo "=== E4 rouster $(date -u +%FT%TZ)"
bash scripts/bench-e4-fib.sh "$FEED" 6
echo "rc-e4-rouster=$?"
echo "=== E4 frr (same-run comparator) $(date -u +%FT%TZ)"
BENCH_E4_MODE=frr bash scripts/bench-e4-fib.sh "$FEED" 6
echo "rc-e4-frr=$?"
echo "=== E2 churn rouster $(date -u +%FT%TZ)"
bash scripts/bench-e2-churn.sh rouster "$ANN" 6
echo "rc-e2-rouster=$?"
echo "=== E2 churn frr $(date -u +%FT%TZ)"
bash scripts/bench-e2-churn.sh frr "$ANN" 6
echo "rc-e2-frr=$?"
echo "=== E7 novel-attribute churn (rouster, 3 runs) $(date -u +%FT%TZ)"
BENCH_E2_NOVEL=1 BENCH_E2_FULL_CYCLES=2 bash scripts/bench-e2-churn.sh rouster "$ANN" 3
echo "rc-e7=$?"
echo "=== E3 sessions rouster (grid) $(date -u +%FT%TZ)"
bash scripts/bench-e3-sessions.sh rouster "$FEED" 6
echo "rc-e3-rouster=$?"
echo "=== E3 sessions frr (grid) $(date -u +%FT%TZ)"
bash scripts/bench-e3-sessions.sh frr "$FEED" 6
echo "rc-e3-frr=$?"
echo "=== suite done $(date -u +%FT%TZ)"
