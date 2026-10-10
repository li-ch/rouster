#!/usr/bin/env bash
# W8 smoke test: the savd daemon end-to-end against a live rousterd.
#
# Repo AGENTS.md testing bar: "SAV: spoofed-traffic tests measuring
# improper block / improper permit", plus the W8 frozen readouts:
# WIRED (savd starts, builds its SIB from the live RIB view over ZAPI,
# installs monitor rules, logs them), RELOAD (SIGHUP with a changed
# config regenerates + diffs), MONITOR-DEFAULT (fresh start drops
# nothing, the spoof counter rises, drop mode refuses without the
# friction line), CLEAN-EXIT (SIGTERM removes every installed rule).
#
# Path (the full Phase-1.5 chain, one container):
#
#   staticd --ZAPI--> rousterd --reconcile--> kernel route
#                            '--redistribute--> savd --Dataplane--> rp_filter
#
# Topology (W7's, reused): the source prefix 198.51.100.0/24's egress is
# vethlegit; ns1 sends the legit leg out vethlegitp (arrives on the
# egress) and the spoof leg out vethspoofp with source 198.51.100.9
# bound (arrives on vethspoof = the wrong interface).
#
# The route comes through the real path now: staticd config
# `ip route 198.51.100.0/25 198.51.100.9` -> rousterd resolves the
# gateway onto vethlegit, programs it, and savd derives its SIB from the
# redistribute push (push form = resolved ifindex hop). The routed
# prefix is a /25, NOT vethlegit's own connected /24: a protocol route
# for the exact connected prefix is masked (CONNECT-table semantics,
# matching zebra's per-prefix-node selection where connected distance 0
# wins) — it would never program nor reach savd's redistribute dump. The
# /25 is its own prefix key, still covers the spoof source .9, and real
# FRR installs it the same way.
#
# The spoof counter feed is real traffic: neighbour (ARP/NDP) events on
# savd's netlink connection are (source, ingress) observations — the
# spoof leg's ARP on vethspoof counts invalid under the strict
# empty-allowlist; the legit leg's neighbour on vethlegit counts valid.
# ARP/NDP granularity, not per-packet (disclosed in the W8 report).
#
# /proc/sys is read-only under the docker backend (W7 probe evidence);
# setup overmounts a fresh procfs — environment prep, the same class as
# `ip link add`. Caps: the z5b/W7 pattern (NET_ADMIN+NET_RAW+SYS_ADMIN;
# no --privileged). Base image frr-testbed:10.2.2 (cached only).
#
#   scripts/test-w8-savd.sh
set -euo pipefail

# Resolve the script dir to an ABSOLUTE path before any cd: the
# quarantine default below anchors on it, and re-resolving a relative
# $0 after the top-level cd silently shifts the base (the 11:02
# orchestrator run's captures landed inside the repo that way).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:w8
NAME=rouster-w8
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
ROUSTERD_LOG=/var/log/rousterd.log
STATICD_LOG=/var/log/staticd.log
SAVD_LOG=/var/log/savd.log
ROUSTERD_CONF=/etc/rouster.conf
STATICD_CONF=/etc/staticd.conf
SAVD_CONF=/etc/savd.conf
ZAPI_SOCK=/run/rouster/zserv.api
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_W8_QUARANTINE:-$SCRIPT_DIR/../../away/2026-10-09/quarantine/w8-savd}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# Poll inside the container until a shell condition holds, or fail.
wait_in_container() {
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

log_grep() { # <file> <pattern>
    docker exec "$NAME" sh -c "grep -q '$2' $1"
}

# Loss percentage of one ping run ("x% packet loss").
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
        "sysctl net.ipv4.conf.vethlegit.rp_filter net.ipv4.conf.vethspoof.rp_filter; \
         ip route show; ip -4 neigh show" \
        > "$QUARANTINE/state.txt" 2>&1 || true
    docker exec "$NAME" sh -c "cat $SAVD_LOG" > "$QUARANTINE/savd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat $ROUSTERD_LOG" > "$QUARANTINE/rousterd.log" 2>&1 || true
    docker exec "$NAME" sh -c \
        'ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1; echo ---; \
         ip netns exec ns1 ping -c3 -W1 -I vethlegitp 198.51.100.1' \
        > "$QUARANTINE/pings.txt" 2>&1 || true
}

# The last logged monitor-count invalid= value (the spoof counter).
spoof_counter() {
    docker exec "$NAME" sh -c \
        "grep 'monitor counts' $SAVD_LOG | tail -1 | grep -o 'invalid=[0-9]*' | cut -d= -f2"
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
trap 'capture; rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
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

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME (cap pattern of test-w7-sav)"
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

echo "==> making /proc/sys writable (fresh procfs overmount; W7 probe evidence)"
docker exec "$NAME" mount -t proc none /proc

echo "==> topology: two veth pairs, peer ends in netns ns1"
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

# M3 (neighbour-liveness gate on the NEXTHOP_UPDATE answer): confirm
# the tracked gateway's neighbour BEFORE staticd registers it, the way a
# deployment with flowing traffic would — one ping from the container
# side ARPs for ns1's 198.51.100.9 and holds the lladdr entry on
# vethlegit (REACHABLE, later STALE — both confirmed for the gate).
docker exec "$NAME" ping -c1 -W1 198.51.100.9 >/dev/null 2>&1 || true
docker exec "$NAME" ip neigh show 198.51.100.9 dev vethlegit | grep -q lladdr

SPOOF_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1'
LEGIT_CMD='ip netns exec ns1 ping -c3 -W1 -I vethlegitp 198.51.100.1'

echo "==> writing configs (rousterd: zapi socket only; staticd: the source-prefix route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  > $ROUSTERD_CONF"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/25 198.51.100.9' \
  > $STATICD_CONF"
docker exec "$NAME" sh -c "printf '%s\n' \
  'interface vethlegit' \
  '  mode strict' \
  'interface vethspoof' \
  '  mode strict' \
  'poll 1' \
  > $SAVD_CONF"

echo "==> [MONITOR-DEFAULT] refusal first: drop config without the friction line"
docker exec "$NAME" sh -c "printf '%s\n' \
  'action drop' \
  'interface vethlegit' \
  '  mode strict' \
  > /tmp/savd-refuse.conf"
if docker exec "$NAME" \
    sh -c "savd --config /tmp/savd-refuse.conf --zapi-socket $ZAPI_SOCK 2>&1" \
    > "$QUARANTINE/refusal.log"; then
    echo "FAIL: savd started in drop mode without i-understand-drop-mode" >&2
    exit 1
fi
grep -q 'i-understand-drop-mode' "$QUARANTINE/refusal.log"
echo "    refused (exit nonzero, friction line named in the message)"

echo "==> starting resident rousterd"
docker exec -d "$NAME" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd zapi server up" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> starting staticd (installs the source-prefix route via ZAPI)"
docker exec -d "$NAME" sh -c "staticd --config $STATICD_CONF --zapi-socket $ZAPI_SOCK > $STATICD_LOG 2>&1"
wait_in_container "route programmed via vethlegit" 40 \
    "ip route show 198.51.100.0/25 | grep -q 'via 198.51.100.9 dev vethlegit'"

echo "==> starting savd (monitor by default)"
docker exec -d "$NAME" sh -c "savd --config $SAVD_CONF --zapi-socket $ZAPI_SOCK > $SAVD_LOG 2>&1"

# WIRED: SIB built from the live RIB view, monitor rules installed, the
# rule set logged.
wait_in_container "savd synced its rib view" 30 "grep -q 'rib view synced' $SAVD_LOG"
log_grep "$SAVD_LOG" "savd: session established"
wait_in_container "savd logged its startup rules" 30 "grep -q 'savd: rule ' $SAVD_LOG"
# Exactly two per-op rule lines (the summary line says `rule set`, not
# `rule rule=`; the field form is the discriminator).
[ "$(docker exec "$NAME" sh -c "grep -c 'savd: rule rule=' $SAVD_LOG")" = 2 ]
log_grep "$SAVD_LOG" "action monitor"
wait_in_container "savd installed the monitor rule set" 30 \
    "grep -q 'rule set installed' $SAVD_LOG"
# The strict rules from the live SIB: the allowlist prefix is the route
# staticd installed, mirrored from the redistribute push.
docker exec "$NAME" sh -c "grep 'savd: rule ' $SAVD_LOG" | grep "198.51.100.0/25"
echo "    WIRED: rib synced, rules logged, monitor program installed"

# ENFORCE (monitor): no kernel drop rule — sysctl stays 0 on both.
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
echo "    ENFORCE(monitor): rp_filter vethlegit=0 vethspoof=0 (no drop rule)"

# MONITOR-DEFAULT: fresh start drops nothing (spoof passes, legit
# passes) and the spoof counter rises with spoofed traffic.
expect_loss "MONITOR-DEFAULT spoof passes" "$SPOOF_CMD" 0
expect_loss "LEGIT-PASS (monitor)" "$LEGIT_CMD" 0
sleep 2 # a poll tick (poll 1) logs fresh counts
C1="$(spoof_counter)"
echo "    spoof counter after first spoof burst: invalid=${C1:-none}"
[ -n "$C1" ] && [ "$C1" -ge 1 ] || {
    echo "FAIL: spoof counter did not rise from the spoof leg" >&2; exit 1; }
# LEGIT traffic counts valid, never spoofed (improper-verdict check).
log_grep "$SAVD_LOG" "valid=[1-9]"

# A second spoof burst after a neighbour flush: the counter rises again.
docker exec "$NAME" ip neigh flush dev vethspoof
docker exec "$NAME" sh -c "$SPOOF_CMD" >/dev/null 2>&1 || true
sleep 2
C2="$(spoof_counter)"
echo "    spoof counter after second spoof burst: invalid=${C2:-none} (was $C1)"
[ -n "$C2" ] && [ "$C2" -gt "$C1" ] || {
    echo "FAIL: spoof counter did not rise again" >&2; exit 1; }

echo "==> [RELOAD] SIGHUP with drop mode + the friction line"
docker exec "$NAME" sh -c "printf '%s\n' \
  'interface vethlegit' \
  '  mode strict' \
  'interface vethspoof' \
  '  mode strict' \
  'action drop' \
  'i-understand-drop-mode yes' \
  'poll 1' \
  > $SAVD_CONF"
docker exec "$NAME" sh -c 'kill -HUP "$(pidof savd)"'
# RELOAD: the changed config regenerated + diffed (monitor ops removed,
# drop ops added).
wait_in_container "reload regenerated the rule set" 30 "grep -q 'rule set changed' $SAVD_LOG"
log_grep "$SAVD_LOG" "savd: rule removed"
log_grep "$SAVD_LOG" "savd: rule added"
log_grep "$SAVD_LOG" "action drop"
# ENFORCE (drop): sysctl values match the generated ops (strict => 1).
wait_in_container "rp_filter flipped to 1" 20 \
    '[ "$(cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 1 ]'
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 1 ]
echo "    ENFORCE(drop): rp_filter vethlegit=1 vethspoof=1 (strict)"

# SPOOF-BLOCK (drop): the spoofed source is blocked (100% loss);
# LEGIT-PASS: the legitimate source still passes (improper block = 0).
expect_loss "SPOOF-BLOCK (drop)" "$SPOOF_CMD" 100
expect_loss "LEGIT-PASS (drop)" "$LEGIT_CMD" 0

echo "==> [CLEAN-EXIT] SIGTERM removes every installed rule"
docker exec "$NAME" sh -c 'kill -TERM "$(pidof savd)"'
wait_in_container "savd exited" 20 '! pidof savd >/dev/null'
log_grep "$SAVD_LOG" "installed rules cleared"
wait_in_container "rp_filter restored to 0" 20 \
    '[ "$(cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]'
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
# No SAV state left behind either (the applied-state file emptied).
[ -z "$(docker exec "$NAME" cat /run/rouster/sav-applied 2>/dev/null)" ]
echo "    CLEAN-EXIT: rp_filter back to 0, applied-state file empty, process gone"

echo "w8 savd smoke test: PASS"
