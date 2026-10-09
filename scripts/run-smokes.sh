#!/usr/bin/env bash
# Sequential smoke-test runner.
#
# Discovers every scripts/test-*.sh (alphabetical, no hardcoded list),
# runs them one at a time, tees each script's output to
# target/smoke-logs/<name>.log, prints a summary table at the end, and
# exits nonzero if any script failed (the whole suite still runs first).
#
# Usage:
#   scripts/run-smokes.sh                # run every discovered smoke test
#   scripts/run-smokes.sh 'z5*'          # run only scripts matching a glob
#   scripts/run-smokes.sh --dry-run      # list what would run, execute nothing
#
# Behaviour notes:
# - Smoke scripts are self-cleaning by convention (docker rm traps); this
#   runner performs no docker cleanup of its own.
# - Before executing anything it runs a 15 s-bounded docker probe (one
#   throwaway container from the cached alpine image — no pulls); if docker
#   is unhealthy or hanging, the runner aborts instead of burning a cargo
#   build. Disable with ROUSTER_SMOKE_PROBE=0 (for testing the runner
#   itself against stub scripts).
# - ROUSTER_SMOKE_DIR overrides the scanned directory (testing hook).
#
# Exit status: the number of failed scripts (0 = all passed); 2 for setup
# errors (no scripts found, bad option, failed docker probe).
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS_DIR="${ROUSTER_SMOKE_DIR:-$REPO_ROOT/scripts}"
LOG_DIR="$REPO_ROOT/target/smoke-logs"
PROBE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-docker.m.daocloud.io/library/alpine:3.20}"

usage() {
    awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
}

dry_run=0
patterns=()
while [ $# -gt 0 ]; do
    case "$1" in
        -n|--dry-run|--list) dry_run=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) printf 'run-smokes: unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
        *) patterns+=("$1") ;;
    esac
    shift
done

# Discover smoke scripts dynamically: every test-*.sh, sorted.
shopt -s nullglob
all_scripts=("$SCRIPTS_DIR"/test-*.sh)
shopt -u nullglob

scripts=()
for s in "${all_scripts[@]}"; do
    name="$(basename "$s")"
    if [ "${#patterns[@]}" -gt 0 ]; then
        matched=0
        for pat in "${patterns[@]}"; do
            # shellcheck disable=SC2254  # glob match against the basename
            case "$name" in $pat) matched=1 ;; esac
        done
        [ "$matched" -eq 1 ] || continue
    fi
    scripts+=("$s")
done

if [ "${#scripts[@]}" -eq 0 ]; then
    printf 'run-smokes: no smoke scripts found in %s\n' "$SCRIPTS_DIR" >&2
    exit 2
fi

if [ "$dry_run" -eq 1 ]; then
    printf 'dry run: %d smoke script(s) would run, in order:\n' "${#scripts[@]}"
    for s in "${scripts[@]}"; do
        printf '  %s\n' "$(basename "$s")"
    done
    exit 0
fi

# Docker pre-flight: one throwaway container, 15 s bound. If docker is
# down or hanging, stop before spending time on cargo builds.
if [ "${ROUSTER_SMOKE_PROBE:-1}" != "0" ]; then
    printf '==> docker pre-flight probe (15 s bound)\n'
    if ! perl -e 'alarm 15; exec @ARGV' docker run --rm "$PROBE_IMAGE" true; then
        printf 'run-smokes: docker probe failed — not running smokes\n' >&2
        exit 2
    fi
fi

if ! mkdir -p "$LOG_DIR"; then
    printf 'run-smokes: cannot create log dir %s\n' "$LOG_DIR" >&2
    exit 2
fi

printf '==> %d smoke script(s) from %s; logs in %s\n' \
    "${#scripts[@]}" "$SCRIPTS_DIR" "$LOG_DIR"

rows=()
failures=0
i=0
suite_start=$SECONDS
for script in "${scripts[@]}"; do
    i=$((i + 1))
    name="$(basename "$script")"
    log="$LOG_DIR/$name.log"
    printf '\n========== [%d/%d] %s ==========\n' "$i" "${#scripts[@]}" "$name"

    if [ ! -x "$script" ]; then
        printf 'run-smokes: %s is not executable\n' "$script" >&2
        rows+=("$name FAIL 0s not-executable")
        failures=$((failures + 1))
        continue
    fi

    start=$SECONDS
    "$script" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
    dur=$((SECONDS - start))

    if [ "$rc" -eq 0 ]; then
        rows+=("$name PASS ${dur}s exit=0")
    else
        rows+=("$name FAIL ${dur}s exit=$rc")
        failures=$((failures + 1))
    fi
done
total=$((SECONDS - suite_start))

printf '\n==================== smoke summary ====================\n'
printf '%-28s %-5s %7s  %s\n' SCRIPT RESULT TIME EXIT
printf -- '-----------------------------------------------------\n'
for row in "${rows[@]}"; do
    # shellcheck disable=SC2086  # fields were assembled with single spaces
    printf '%-28s %-5s %7s  %s\n' $row
done
printf -- '-----------------------------------------------------\n'
printf '%d run, %d pass, %d fail — %ds total\n' \
    "${#rows[@]}" "$(( ${#rows[@]} - failures ))" "$failures" "$total"

if [ "$failures" -gt 0 ]; then
    # Keep the exit status well away from 256-wraparound territory.
    [ "$failures" -gt 125 ] && failures=125
    exit "$failures"
fi
exit 0
