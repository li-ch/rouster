#!/usr/bin/env bash
# ADD-C1 smoke test: the savd daemon end-to-end on the nft backend —
# the real binary with `backend nft` in its config.
#
# N6B §Deferred 1 (N6 §Deferred 2 before it): scripts/test-sav-nft.sh
# proves the nft backend through the w7-sav-smoke EXAMPLE (one process
# driving the Dataplane trait directly), and scripts/test-w8-savd.sh
# proves the savd DAEMON through the rp_filter backend — this leg
# crosses them. The full chain, one container:
#
#   staticd --ZAPI--> rousterd --reconcile--> kernel route
#                            '--redistribute--> savd --Dataplane--> nft
#
# Frozen readouts:
#   WIRED           savd builds its SIB from the live RIB view over
#                   ZAPI, installs the compiled allowlist CONTENT as
#                   `table inet rouster_sav` in the kernel (prerouting
#                   hook, named counters), writes its run-dir ruleset
#                   and applied-marker files, and the status file
#                   (`savd --show`) carries `backend nft`.
#   MONITOR-DEFAULT fresh start drops nothing: spoof and legit both
#                   pass, sysctls stay 0, and the KERNEL counters
#                   diverge — the spoof op's count line holds the
#                   invalid packets, the legit op's the valid ones,
#                   `monitor source dataplane` (the nft rows, not the
#                   neighbour-event simulation W8's backend fed it).
#   RELOAD          SIGHUP with `action drop` (+ the friction line,
#                   backend unchanged) regenerates + diffs and swaps
#                   the table: spoof 100% loss, legit 0% loss, and
#                   rp_filter still 0 on every leg — the differential
#                   the sysctl backend cannot express without touching
#                   procfs. Dropped packets still count (the counter
#                   rides the deny rule).
#   CLEAN-EXIT      SIGTERM destroys the table, removes the ruleset
#                   and marker files, the status file and the pidfile;
#                   the spoof passes again.
#
# Image: test-sav-nft.sh's — rouster-nft:local (busybox + nftables
# v1.0.9, the cached image; no pulls), with full iproute2 `ip`
# docker-cp'd in from frr-testbed:10.2.2 (busybox `ip` has no netns
# subcommand) — the same binary-delivery class as the daemon binaries
# themselves. Topology: W7's/W8's shape — the source prefix
# 198.51.100.0/24's egress is vethlegit; ns1 sends the legit leg out
# vethlegitp and the spoof leg out vethspoofp with source 198.51.100.9
# bound (arrives on vethspoof = the wrong interface).
#
# staticd's route is a /25, NOT vethlegit's connected /24 (W8's note):
# a protocol route for the exact connected prefix is masked by
# CONNECT-table semantics; the /25 is its own prefix key, still covers
# the spoof source .9, and real FRR installs it the same way.
#
# No procfs overmount: the nft backend writes no sysctls — that is the
# point of the leg (drop mode holds with rp_filter still 0) — and the
# rp_filter values the assertions read are readable on the read-only
# mount.
#
#   scripts/test-savd-nft.sh
set -euo pipefail

# Resolve the script dir to an ABSOLUTE path before any cd: the
# quarantine default below anchors on it (the test-sav-nft.sh lesson).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:savd-nft
NAME=rouster-savd-nft
BASE_IMAGE="${ROUSTER_SAVD_NFT_BASE_IMAGE:-rouster-nft:local}"
IP_DONOR="${ROUSTER_SAVD_NFT_IP_DONOR:-frr-testbed:10.2.2}"
DONOR=rouster-savd-nft-ip-donor
ROUSTERD_LOG=/var/log/rousterd.log
STATICD_LOG=/var/log/staticd.log
SAVD_LOG=/var/log/savd.log
ROUSTERD_CONF=/etc/rouster.conf
STATICD_CONF=/etc/staticd.conf
SAVD_CONF=/etc/savd.conf
ZAPI_SOCK=/run/rouster/zserv.api
STATUS_FILE=/run/rouster/savd.status
RULESET_FILE=/run/rouster/sav-nft.ruleset
MARKER_FILE=/run/rouster/sav-nft-applied
PIDFILE=/run/rouster/savd.pid
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_SAVD_NFT_QUARANTINE:-$SCRIPT_DIR/../../away/2026-10-11/night/quarantine/add-c1}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# Poll inside the container until a shell condition holds, or fail.
wait_in_container() { # <desc> <attempts> <body>
    local desc="$1" attempts="$2" body="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$NAME" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (waited $((attempts / 2))s)" >&2
    docker exec "$NAME" sh -c \
        "tail -30 $ROUSTERD_LOG; tail -30 $STATICD_LOG; tail -40 $SAVD_LOG" >&2 || true
    return 1
}

# Poll `savd --show` (the status file) until a condition on its text
# holds — the counts ride the poll cadence, so the file lags traffic.
wait_status() { # <desc> <attempts> <egrep-pattern>
    local desc="$1" attempts="$2" pattern="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$NAME" savd --show 2>/dev/null | grep -Eq "$pattern"; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (status never matched: $pattern)" >&2
    docker exec "$NAME" savd --show 1>&2 || true
    docker exec "$NAME" sh -c "tail -40 $SAVD_LOG" >&2 || true
    return 1
}

# The status file's count line for one ifindex, one tallies field. The
# leading space anchors the field: `valid=` alone would also match
# inside `invalid=15` (the test-sav-nft.sh readout convention).
count_field() { # <ifindex> <field invalid|valid>
    docker exec "$NAME" savd --show 2>/dev/null \
        | grep "^count iba permit #$1 " \
        | grep -o " $2=[0-9]*" | head -1 | cut -d= -f2
}

log_grep() { # <file> <pattern> — grep INSIDE the container (the W8
    # idiom): no host-side pipeline for pipefail to bite on.
    docker exec "$NAME" sh -c "grep -q '$2' $1"
}

# Loss percentage of one ping run ("x% packet loss"). busybox ping
# exits nonzero on 100% loss — that is the answer, not an error.
ping_loss() {
    docker exec "$NAME" sh -c "$1; true" 2>/dev/null \
        | grep -o '[0-9]*% packet loss' | head -1 | cut -d% -f1
}

expect_loss() { # <label> <command> <expected %>
    local got
    got="$(ping_loss "$2")"
    echo "    $1: loss=${got:-NO-ANSWER}% (want $3%)"
    [ "${got:-100}" = "$3" ]
}

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$NAME" sh -c \
        "nft list ruleset; echo ---; ip -br addr show; ip route show; \
         ip netns exec ns1 ip route show; echo ---; \
         cat $RULESET_FILE 2>/dev/null; echo ---; cat $MARKER_FILE 2>/dev/null; echo ---; \
         cat $STATUS_FILE 2>/dev/null; echo ---; \
         sysctl net.ipv4.conf.vethlegit.rp_filter net.ipv4.conf.vethspoof.rp_filter" \
        > "$QUARANTINE/state.txt" 2>&1 || true
    docker exec "$NAME" sh -c "cat $SAVD_LOG" > "$QUARANTINE/savd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat $ROUSTERD_LOG" > "$QUARANTINE/rousterd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat $STATICD_LOG" > "$QUARANTINE/staticd.log" 2>&1 || true
    docker exec "$NAME" sh -c \
        'ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1; echo ---; \
         ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 198.51.100.1' \
        > "$QUARANTINE/pings.txt" 2>&1 || true
}

echo "==> building rousterd + staticd + savd ($MUSL_TARGET, release)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin staticd
cargo build --release --target "$MUSL_TARGET" -p sav --bin savd

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; \
      docker rm -f "$NAME" "$DONOR" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cp "target/$MUSL_TARGET/release/staticd" "$BUILD_DIR/staticd"
cp "target/$MUSL_TARGET/release/savd" "$BUILD_DIR/savd"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
COPY staticd /usr/local/bin/staticd
COPY savd /usr/local/bin/savd
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" "$DONOR" >/dev/null 2>&1 || true

echo "==> starting container $NAME (cap pattern of test-sav-nft)"
# apparmor=unconfined: docker's default AppArmor profile carries an
# unconditional `deny mount` (moby profiles/apparmor/template.go) that
# overrides CAP_SYS_ADMIN wherever the LSM is active — Ubuntu runners
# answer the /proc overmount and the `ip netns add` bind-mount with
# "Permission denied" (CI run 38647649951). Locally (no AppArmor on
# the docker VM) this changes nothing; seccomp already permits mount
# for SYS_ADMIN-bounded containers.
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

# Environment parity, not a test leg (the w7/sav-nft note): zero the
# netns rp_filter templates before the baseline asserts so hosts that
# default container netns to loose uRPF cannot shadow the
# differential.
docker exec "$NAME" mount -t proc none /proc
docker exec "$NAME" sysctl -q -w \
    net.ipv4.conf.all.rp_filter=0 \
    net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.lo.rp_filter=0

echo "==> delivering full iproute2 ip (busybox has no netns subcommand)"
docker create --name "$DONOR" "$IP_DONOR" >/dev/null
docker cp "$DONOR:/sbin/ip" "$BUILD_DIR/ip"
# The shared libs are symlinks in the donor (docker cp would preserve
# them as dangling links), so copy each REAL file and re-point the
# soname link inside the container.
for lib in libelf.so.1 libcap.so.2 libz.so.1 libzstd.so.1; do
    real="$(docker run --rm --entrypoint sh "$IP_DONOR" -c "readlink -f /usr/lib/$lib")"
    docker cp "$DONOR:$real" "$BUILD_DIR/$(basename "$real")"
done
docker rm -f "$DONOR" >/dev/null
docker cp "$BUILD_DIR/ip" "$NAME:/usr/local/bin/ip"
for lib in libelf.so.1 libcap.so.2 libz.so.1 libzstd.so.1; do
    real="$(docker run --rm --entrypoint sh "$IP_DONOR" -c "readlink -f /usr/lib/$lib")"
    docker cp "$BUILD_DIR/$(basename "$real")" "$NAME:$real"
    docker exec "$NAME" ln -sf "$(basename "$real")" "/usr/lib/$lib"
done
docker exec "$NAME" ip -V

echo "==> baseline: no rouster table, no sysctl touches"
[ -z "$(docker exec "$NAME" nft list ruleset)" ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/lo/rp_filter)" = 0 ]

echo "==> topology: two veth pairs, peer ends in netns ns1 (W7/W8 shape)"
docker exec "$NAME" ip link add vethlegit type veth peer name vethlegitp
docker exec "$NAME" ip link add vethspoof type veth peer name vethspoofp
docker exec "$NAME" ip netns add ns1
docker exec "$NAME" ip link set vethlegitp netns ns1
docker exec "$NAME" ip link set vethspoofp netns ns1
docker exec "$NAME" ip addr add 198.51.100.1/24 dev vethlegit
docker exec "$NAME" ip addr add 192.0.2.1/24 dev vethspoof
docker exec "$NAME" ip link set vethlegit up
docker exec "$NAME" ip link set vethspoof up
docker exec "$NAME" ip netns exec ns1 ip addr add 198.51.100.9/24 dev vethlegitp
docker exec "$NAME" ip netns exec ns1 ip addr add 192.0.2.9/24 dev vethspoofp
docker exec "$NAME" ip netns exec ns1 ip link set vethlegitp up
docker exec "$NAME" ip netns exec ns1 ip link set vethspoofp up
docker exec "$NAME" ip netns exec ns1 ip link set lo up

LEGIT_IF="$(docker exec "$NAME" cat /sys/class/net/vethlegit/ifindex)"
SPOOF_IF="$(docker exec "$NAME" cat /sys/class/net/vethspoof/ifindex)"
echo "    vethlegit ifindex=$LEGIT_IF  vethspoof ifindex=$SPOOF_IF"

# Neighbour-liveness gate (W8's M3): confirm the tracked gateway's
# neighbour BEFORE staticd registers it, the way a deployment with
# flowing traffic would — one ping ARPs for ns1's 198.51.100.9 and
# holds the lladdr entry on vethlegit.
docker exec "$NAME" ping -c1 -W1 198.51.100.9 >/dev/null 2>&1 || true
docker exec "$NAME" ip neigh show 198.51.100.9 dev vethlegit | grep -q lladdr

SPOOF_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1'
LEGIT_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 198.51.100.1'

echo "==> writing configs (savd: backend nft, strict, monitor, poll 1)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  > $ROUSTERD_CONF"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/25 198.51.100.9' \
  > $STATICD_CONF"
docker exec "$NAME" sh -c "printf '%s\n' \
  'backend nft' \
  'interface vethlegit' \
  '  mode strict' \
  'interface vethspoof' \
  '  mode strict' \
  'poll 1' \
  > $SAVD_CONF"

echo "==> starting resident rousterd"
docker exec -d "$NAME" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd zapi server up" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> starting staticd (installs the source-prefix route via ZAPI)"
docker exec -d "$NAME" sh -c "staticd --config $STATICD_CONF --zapi-socket $ZAPI_SOCK > $STATICD_LOG 2>&1"
wait_in_container "route programmed via vethlegit" 40 \
    "ip route show 198.51.100.0/25 | grep -q 'via 198.51.100.9 dev vethlegit'"

echo "==> starting savd (backend nft, monitor by default)"
docker exec -d "$NAME" sh -c "savd --config $SAVD_CONF --zapi-socket $ZAPI_SOCK > $SAVD_LOG 2>&1"

# WIRED: SIB built from the live RIB view, the compiled allowlist
# content installed as the kernel nft table.
wait_in_container "savd synced its rib view" 30 "grep -q 'rib view synced' $SAVD_LOG"
wait_in_container "savd logged its startup rules" 30 "grep -q 'savd: rule ' $SAVD_LOG"
# Exactly two per-op rule lines (the summary line says `rule set`, not
# `rule rule=`; the field form is the discriminator).
[ "$(docker exec "$NAME" sh -c "grep -c 'savd: rule rule=' $SAVD_LOG")" = 2 ]
# The config the daemon loaded names the nft backend (not the default
# rp_filter — the whole leg rides on this knob).
log_grep "$SAVD_LOG" 'config loaded.*backend nft'
wait_in_container "savd installed the monitor rule set" 30 \
    "grep -q 'rule set installed' $SAVD_LOG"
# The strict rules from the live SIB: the allowlist carries the route
# staticd installed, mirrored from the redistribute push.
docker exec "$NAME" sh -c "grep 'savd: rule ' $SAVD_LOG" | grep "198.51.100.0/25"
echo "    WIRED: rib synced, rules logged, backend nft config loaded"

# ENFORCE (monitor): the kernel holds the counter-bearing table —
# prerouting hook, named counters, no drop verdict anywhere — and the
# sysctl surface is untouched. The log line fires just BEFORE the
# install call, so the table itself is waited on, not assumed.
wait_in_container "nft table live in the kernel" 20 \
    "nft list table inet rouster_sav | grep -q prerouting"
docker exec "$NAME" nft list table inet rouster_sav >"$QUARANTINE/monitor-ruleset.txt"
grep -q 'hook prerouting priority raw' "$QUARANTINE/monitor-ruleset.txt"
grep -q "counter name \"i_vethspoof" "$QUARANTINE/monitor-ruleset.txt"
! grep -qw drop "$QUARANTINE/monitor-ruleset.txt"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
# Operator evidence on disk: the ruleset file and the applied marker.
wait_in_container "run-dir evidence written" 20 \
    "[ -s $RULESET_FILE ] && [ -s $MARKER_FILE ]"
grep -q 'table inet rouster_sav' "$QUARANTINE/monitor-ruleset.txt"
echo "    ENFORCE(monitor): table in kernel (counters, no drop), rp_filter 0/0, run-dir files written"

# STATUS: `savd --show` — the run-dir surface, no log greps: the
# running config names the backend, the installed rule count, and the
# monitor line already answers from the dataplane. (2>/dev/null: the
# binary's tracing init logs "savd starting" to stderr even for
# --show.)
wait_status "status published with backend nft" 20 'config .*backend nft'
docker exec "$NAME" savd --show >"$QUARANTINE/status-monitor.txt" 2>/dev/null
grep -q '^installed 2 rules' "$QUARANTINE/status-monitor.txt"
grep -q '^monitor source dataplane invalid=' "$QUARANTINE/status-monitor.txt"
echo "    STATUS: savd --show carries backend nft, 2 rules, monitor source dataplane"

# MONITOR-DEFAULT: nothing drops (spoof and legit both pass) and the
# KERNEL counters diverge — the nft rows the status file's per-op
# count lines render (N6B), not the neighbour-event simulation. The
# space before `valid=` keeps `invalid=15` from satisfying it.
expect_loss "MONITOR-DEFAULT spoof passes" "$SPOOF_CMD" 0
expect_loss "LEGIT-PASS (monitor)" "$LEGIT_CMD" 0
wait_status "spoof op counted its invalid packets" 20 \
    "count iba permit #$SPOOF_IF .* monitor .* invalid=[1-9][0-9]*"
wait_status "legit op counted its valid packets" 20 \
    "count iba permit #$LEGIT_IF .* monitor .* valid=[1-9][0-9]*"
SPOOF_INV="$(count_field "$SPOOF_IF" invalid)"
LEGIT_VAL="$(count_field "$LEGIT_IF" valid)"
echo "    MONITOR-DEFAULT: kernel counters diverged (spoof op invalid=$SPOOF_INV, legit op valid=$LEGIT_VAL)"
[ -n "$SPOOF_INV" ] && [ "$SPOOF_INV" -ge 3 ]
[ -n "$LEGIT_VAL" ] && [ "$LEGIT_VAL" -ge 3 ]
# The log's monitor line names the dataplane source too (the LAST
# monitor-counts line — all greps inside the container).
log_grep_last() { # <file> <grep-for> <pattern-on-last-line>
    docker exec "$NAME" sh -c "$2 $1 | tail -1 | grep -q '$3'"
}
log_grep_last "$SAVD_LOG" "grep 'monitor counts'" 'source=dataplane'
docker exec "$NAME" savd --show >"$QUARANTINE/status-counted.txt" 2>/dev/null

echo "==> [RELOAD] SIGHUP with drop mode + the friction line (backend unchanged)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'backend nft' \
  'interface vethlegit' \
  '  mode strict' \
  'interface vethspoof' \
  '  mode strict' \
  'action drop' \
  'i-understand-drop-mode yes' \
  'poll 1' \
  > $SAVD_CONF"
docker exec "$NAME" sh -c 'kill -HUP "$(pidof savd)"'
# RELOAD: the changed config regenerated + diffed — monitor ops
# removed, drop ops added (the daemon swapped the whole table).
wait_in_container "reload swapped in the drop rules" 30 \
    "grep 'rule added' $SAVD_LOG | grep -q 'strict drop'"
log_grep "$SAVD_LOG" 'rule removed rule=.* strict monitor'
# ENFORCE (drop): the deny is in force in the nft table, NOT in
# sysctls — the differential the rp_filter backend cannot express.
wait_in_container "drop verdicts live in the kernel table" 20 \
    "nft list table inet rouster_sav | grep -qw drop"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
docker exec "$NAME" nft list table inet rouster_sav >"$QUARANTINE/drop-ruleset.txt"
echo "    ENFORCE(drop): deny verdicts in the nft table; rp_filter still 0/0"

# SPOOF-BLOCK: the spoofed source is 100% blocked; the legit source
# still passes (improper block = 0). Dropped packets still count (the
# counter rides the deny rule) — the fresh table's counters start at
# zero, so the post-burst readback is a clean delta.
expect_loss "SPOOF-BLOCK (drop)" "$SPOOF_CMD" 100
expect_loss "LEGIT-PASS (drop)" "$LEGIT_CMD" 0
wait_status "dropped spoof packets still counted" 20 \
    "count iba permit #$SPOOF_IF .* drop .* invalid=[1-9][0-9]*"
DROP_INV="$(count_field "$SPOOF_IF" invalid)"
echo "    SPOOF-BLOCK: spoof 100% loss, legit 0% loss, invalid counter $DROP_INV (deny-rule counter)"
[ -n "$DROP_INV" ] && [ "$DROP_INV" -ge 3 ]
docker exec "$NAME" savd --show >"$QUARANTINE/status-drop.txt" 2>/dev/null
# The reloaded running config kept the backend and gained drop; the
# installed rules render the drop action.
grep -q 'action drop .*backend nft' "$QUARANTINE/status-drop.txt"
grep -Eq '^rule allow if#[0-9]+ .* strict drop' "$QUARANTINE/status-drop.txt"

echo "==> [CLEAN-EXIT] SIGTERM removes every installed rule"
docker exec "$NAME" sh -c 'kill -TERM "$(pidof savd)"'
wait_in_container "savd exited" 20 '! pidof savd >/dev/null'
docker exec "$NAME" sh -c "grep -q 'installed rules cleared' $SAVD_LOG"
docker exec "$NAME" sh -c "grep -q 'sav nft table destroyed' $SAVD_LOG"
# The kernel table is gone, the run-dir evidence with it.
if docker exec "$NAME" nft list table inet rouster_sav >/dev/null 2>&1; then
    echo "table still present after clear" >&2; exit 1
fi
docker exec "$NAME" sh -c \
    "[ ! -e $RULESET_FILE ] && [ ! -e $MARKER_FILE ] \
     && [ ! -e $STATUS_FILE ] && [ ! -e $PIDFILE ]"
# `savd --show` without a status file is the not-running answer.
if docker exec "$NAME" savd --show >/dev/null 2>&1; then
    echo "savd --show answered with no status file" >&2; exit 1
fi
expect_loss "post-clear spoof passes again" "$SPOOF_CMD" 0
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
echo "    CLEAN-EXIT: table/ruleset/marker/status/pidfile gone, spoof passes, rp_filter 0/0"

echo "savd nft smoke test: PASS"
