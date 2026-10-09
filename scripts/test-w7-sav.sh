#!/usr/bin/env bash
# W7 smoke test: SAV enforcement behind the Dataplane trait, proven with
# spoofed-traffic tests in a container (repo AGENTS.md testing bar:
# "SAV: spoofed-traffic tests measuring improper block / improper permit").
#
# Backend (pre-registered choice order; probe evidence in
# away/2026-10-09/quarantine/B8-enforcement-surface.md + the W7 report):
# nft is ABSENT from every cached image, so enforcement runs on the
# rp_filter sysctl fallback. The container's /proc/sys is mounted
# read-only by the docker backend even with NET_ADMIN+SYS_ADMIN, so
# setup overmounts a fresh procfs (rw) at /proc — environment prep,
# same class as `ip link add`; the binary itself writes only the
# canonical /proc/sys paths, through the Dataplane trait.
#
# Topology (one container; veth pairs because a spoofed packet needs a
# real RX path — the prompt's dummy0 sketch cannot receive; the
# source-prefix egress holder is a veth into a child netns so the
# legitimate leg's replies can return):
#
#   parent ns: vethlegit 198.51.100.1/24   (egress of the source prefix)
#              vethspoof 192.0.2.1/24      (wrong arrival interface)
#   ns1:       vethlegitp 198.51.100.9/24  (the "remote" spoofer/host)
#              vethspoofp 192.0.2.9/24
#
#   legit  = ns1 -> 198.51.100.1 out vethlegitp : arrives on vethlegit
#            (source prefix egress == arrival)              -> passes
#   spoof  = ns1 -> 192.0.2.1 out vethspoofp with source 198.51.100.9:
#            arrives on vethspoof (egress is vethlegit)     -> martian
#            under strict rp_filter (RFC 3704 §2.2), passes loose/monitor.
#
# Readouts asserted: ENFORCE (sysctl values match the generated ops),
# SPOOF-BLOCK (drop mode: spoofed 100% loss), LEGIT-PASS (legit 0% loss
# in BOTH modes — improper block = 0), MONITOR-DEFAULT (monitor mode:
# spoof passes + simulated spoof counter increments), plus clear.
#
# Base image: frr-testbed:10.2.2 (full iproute2 for netns/veth +
# iputils ping). Cached only. Caps: the z5/z5b script pattern
# (NET_ADMIN+NET_RAW+SYS_ADMIN; no --privileged).
#
#   scripts/test-w7-sav.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:w7
NAME=rouster-w7
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_W7_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/w7-sav}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$NAME" sh -c \
        "sysctl net.ipv4.conf.vethlegit.rp_filter net.ipv4.conf.vethspoof.rp_filter; \
         ip -br addr show; ip route show; ip netns exec ns1 ip route show" \
        > "$QUARANTINE/state.txt" 2>&1 || true
    docker exec "$NAME" sh -c \
        'ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1; echo ---; \
         ip netns exec ns1 ping -c3 -W1 -I vethlegitp 198.51.100.1' \
        > "$QUARANTINE/pings.txt" 2>&1 || true
}

# Loss percentage of one ping run ("x% packet loss").
ping_loss() {
    # ping exits nonzero on 100% loss -- that is the answer, not an
    # error (set -o pipefail would otherwise fail the substitution).
    docker exec "$NAME" sh -c "$1; true" 2>/dev/null \
        | grep -o '[0-9]*% packet loss' | head -1 | cut -d% -f1
}

expect_loss() { # <label> <command> <expected %>
    local got
    got="$(ping_loss "$2")"
    echo "    $1: loss=${got:-NO-ANSWER}% (want $3%)"
    [ "${got:-100}" = "$3" ]
}

echo "==> building w7-sav-smoke ($MUSL_TARGET, release, sav example)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" -p sav --example w7-sav-smoke

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/examples/w7-sav-smoke" "$BUILD_DIR/w7-sav-smoke"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY w7-sav-smoke /usr/local/bin/w7-sav-smoke
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME (cap pattern of test-z5b)"
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

echo "==> making /proc/sys writable (fresh procfs overmount; rw probe evidence in the W7 report)"
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

LEGIT_IF="$(docker exec "$NAME" cat /sys/class/net/vethlegit/ifindex)"
SPOOF_IF="$(docker exec "$NAME" cat /sys/class/net/vethspoof/ifindex)"
echo "    vethlegit ifindex=$LEGIT_IF  vethspoof ifindex=$SPOOF_IF"

SPOOF_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1'
LEGIT_CMD='ip netns exec ns1 ping -c3 -W1 -I vethlegitp 198.51.100.1'

echo "==> [monitor leg] install strict IBA with the default Monitor action"
docker exec "$NAME" w7-sav-smoke install --mode strict --action monitor \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    >"$QUARANTINE/monitor-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/monitor-install.log"
# ENFORCE (monitor): the kernel holds no drop rule — sysctl stays 0.
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
echo "    ENFORCE(monitor): rp_filter vethspoof=0 vethlegit=0"

# MONITOR-DEFAULT: default monitor drops nothing (spoof passes)...
expect_loss "MONITOR-DEFAULT spoof passes" "$SPOOF_CMD" 0
# ...and LEGIT-PASS holds in monitor mode.
expect_loss "LEGIT-PASS (monitor)" "$LEGIT_CMD" 0

# The spoof counter increments (route-lookup simulation; the sysctl
# backend has no kernel counters — pre-registered fallback).
docker exec "$NAME" w7-sav-smoke simulate --mode strict --action monitor \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    --observe "198.51.100.9@$SPOOF_IF" >"$QUARANTINE/simulate.log" 2>&1
grep -q 'sav-monitor: invalid=1' "$QUARANTINE/simulate.log"
echo "    MONITOR-DEFAULT: spoof counter incremented (invalid=1)"

echo "==> [drop leg] install strict IBA with the explicit Drop action"
docker exec "$NAME" w7-sav-smoke install --mode strict --action drop \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    >"$QUARANTINE/drop-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/drop-install.log"
# ENFORCE (drop): sysctl values match the generated ops (strict => 1).
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 1 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 1 ]
echo "    ENFORCE(drop): rp_filter vethspoof=1 vethlegit=1 (strict)"

# SPOOF-BLOCK: the spoofed source is blocked (100% loss).
expect_loss "SPOOF-BLOCK (drop)" "$SPOOF_CMD" 100
# LEGIT-PASS: the legitimate source passes in drop mode too —
# improper block = 0 across both modes.
expect_loss "LEGIT-PASS (drop)" "$LEGIT_CMD" 0

echo "==> [bonus] loose drop maps to rp_filter=2 and the spoof passes again (RFC 3704 §2.5)"
docker exec "$NAME" w7-sav-smoke install --mode loose --action drop \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    >"$QUARANTINE/loose-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/loose-install.log"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 2 ]
expect_loss "loose spoof passes" "$SPOOF_CMD" 0

echo "==> clear restores pre-SAV values"
docker exec "$NAME" w7-sav-smoke clear >"$QUARANTINE/clear.log" 2>&1
grep -q 'sav-clear ok' "$QUARANTINE/clear.log"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
echo "    clear: rp_filter back to 0 on both"

echo "w7 sav spoof test: PASS"
