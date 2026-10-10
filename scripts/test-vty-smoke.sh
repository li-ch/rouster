#!/usr/bin/env bash
# VTY smoke test: the operator surfaces end-to-end in one container.
#
# Drives a live rousterd (publishing /run/rouster/rousterd.status on
# its reconcile cadence), savd, bfdd, and vtyd, then runs 4-6 vty
# commands through `vtyd --command` (the vtysh -c analog) plus a
# rousterctl leg — asserting REAL CONTENT, never just exit codes (the
# B7 §4.2 lesson: verify state, don't trust rc).
#
# Covered:
#   - rousterd's dump: interfaces (incl. a VRF device + enslaved
#     member), the neighbour mirror (a real ARP entry), per-table
#     counts with the VRF association
#   - vty grammar: `show interface`, `show ip interface <name>`,
#     `show neighbor [prefix]`, `show vrf`, `show ip route summary`
#     (the W2-f additions) + the pre-existing `show sav`/`show bfd
#     summary` against the sibling daemons
#   - rousterctl's dump consumers (show interface / vrf / rib
#     summary / neighbour / status) over the same live run dir
#
# Topology: two veth pairs; one enslaved to a VRF device (table
# 1001); a ping seeds the ARP neighbour. Caps: NET_ADMIN+NET_RAW
# (no --privileged). Base image frr-testbed:10.2.2 (cached only, no
# pulls).
#
#   scripts/test-vty-smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:vty-smoke
NAME=rouster-vty-smoke
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
RUN_DIR=/run/rouster
ROUSTERD_LOG=/var/log/rousterd.log
SAVD_LOG=/var/log/savd.log
BFDD_LOG=/var/log/bfdd.log
VTYD_LOG=/var/log/vtyd.log
VTYD_ADDR=127.0.0.1:2626

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *)             MUSL_TARGET=x86_64-unknown-linux-musl ;;
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
        "tail -30 $ROUSTERD_LOG; tail -20 $SAVD_LOG; tail -20 $BFDD_LOG; tail -20 $VTYD_LOG" >&2 || true
    return 1
}

# One vtyd one-shot command; the body must contain the pattern.
vty_must_contain() {
    local command="$1" pattern="$2"
    local body
    body="$(docker exec "$NAME" vtyd --command "$command" 2>&1)" || {
        echo "FAIL: \`$command\` exited nonzero" >&2; return 1; }
    echo "$body" | grep -q "$pattern" || {
        echo "FAIL: \`$command\` output lacked \`$pattern\`:" >&2
        echo "$body" | sed 's/^/    | /' >&2
        return 1; }
    echo "    vty: \`$command\` -> contains \`$pattern\`"
}

# One rousterctl invocation over the live run dir.
ctl_must_contain() {
    local args="$1" pattern="$2"
    local body
    body="$(docker exec "$NAME" rousterctl --run-dir "$RUN_DIR" $args 2>&1)" || {
        echo "FAIL: rousterctl $args exited nonzero" >&2; return 1; }
    echo "$body" | grep -q "$pattern" || {
        echo "FAIL: \`rousterctl $args\` lacked \`$pattern\`:" >&2
        echo "$body" | sed 's/^/    | /' >&2
        return 1; }
    echo "    ctl: \`$args\` -> contains \`$pattern\`"
}

echo "==> building rousterd, savd, bfdd, vtyd, rousterctl ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd
cargo build --release --target "$MUSL_TARGET" -p sav --bin savd
cargo build --release --target "$MUSL_TARGET" -p bfdd --bin bfdd
cargo build --release --target "$MUSL_TARGET" -p vty --bin vtyd
cargo build --release --target "$MUSL_TARGET" -p rousterctl --bin rousterctl

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
for bin in rousterd savd bfdd vtyd rousterctl; do
    cp "target/$MUSL_TARGET/release/$bin" "$BUILD_DIR/$bin"
done
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
COPY savd /usr/local/bin/savd
COPY bfdd /usr/local/bin/bfdd
COPY vtyd /usr/local/bin/vtyd
COPY rousterctl /usr/local/bin/rousterctl
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true
echo "==> starting container $NAME"
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

echo "==> topology: two veth pairs, one enslaved to VRF vrf-blue (table 1001)"
docker exec "$NAME" ip link add veth0 type veth peer name veth0p
docker exec "$NAME" ip link add veth1 type veth peer name veth1p
docker exec "$NAME" ip addr add 192.0.2.1/24 dev veth0
docker exec "$NAME" ip addr add 2001:db8:ffff::1/64 dev veth0
docker exec "$NAME" ip addr add 198.51.100.1/24 dev veth1
docker exec "$NAME" ip link add vrf-blue type vrf table 1001
docker exec "$NAME" ip link set veth1 master vrf-blue
docker exec "$NAME" ip link set veth0 up
docker exec "$NAME" ip link set veth1 up
docker exec "$NAME" ip link set veth1p up
docker exec "$NAME" ip link set vrf-blue up

# Seed the neighbour mirror: the peer end moves to netns `peer` so
# the seed ping ARPs for a REAL remote address (a same-netns peer
# address would answer over loopback and never ARP). `ip netns add`
# bind-mounts, hence SYS_ADMIN (the w8 cap pattern).
docker exec "$NAME" ip netns add peer
docker exec "$NAME" ip link set veth0p netns peer
docker exec "$NAME" ip netns exec peer ip addr add 192.0.2.9/24 dev veth0p
docker exec "$NAME" ip netns exec peer ip link set veth0p up
docker exec "$NAME" ip netns exec peer ip link set lo up
docker exec "$NAME" ping -c1 -W1 192.0.2.9 >/dev/null 2>&1 || true
docker exec "$NAME" ip neigh show dev veth0 | grep -q lladdr

echo "==> starting resident rousterd (zapi socket; dump on the reconcile cadence)"
docker exec "$NAME" mkdir -p "$RUN_DIR"
docker exec "$NAME" sh -c "printf '%s\n' 'zapi socket $RUN_DIR/zserv.api' > /etc/rouster.conf"
docker exec -d "$NAME" sh -c "rousterd --config /etc/rouster.conf > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd status dump published" 30 \
    "test -s $RUN_DIR/rousterd.status"
# The dump must carry the real mirrored state.
docker exec "$NAME" cat "$RUN_DIR/rousterd.status" | grep -q "interface veth0"
docker exec "$NAME" cat "$RUN_DIR/rousterd.status" | grep -q "vrf-table 1001"
docker exec "$NAME" cat "$RUN_DIR/rousterd.status" | grep -q "neighbour 192.0.2.9"
echo "    rousterd.status: interfaces + vrf + neighbour present"

echo "==> starting savd and bfdd (the sibling run-dir publishers)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'interface veth0' \
  '  mode strict' \
  'poll 1' \
  > /etc/savd.conf"
docker exec -d "$NAME" sh -c \
    "savd --config /etc/savd.conf --zapi-socket $RUN_DIR/zserv.api > $SAVD_LOG 2>&1"
wait_in_container "savd published its status" 30 "test -s $RUN_DIR/savd.status"

docker exec "$NAME" sh -c "printf '%s\n' 'peer 203.0.113.1' > /etc/bfdd.conf"
docker exec -d "$NAME" sh -c "bfdd --config /etc/bfdd.conf > $BFDD_LOG 2>&1"
wait_in_container "bfdd published its status" 30 "test -s $RUN_DIR/bfdd.status"

echo "==> starting vtyd"
docker exec -d "$NAME" sh -c \
    "vtyd --run-dir $RUN_DIR --bind 127.0.0.1 --port 2626 > $VTYD_LOG 2>&1"
wait_in_container "vtyd answering one-shots" 30 \
    "vtyd --command 'show version' | grep -q 'Rouster vtyd'"

echo "==> the vty command leg (content, not exit codes)"
vty_must_contain "show version"        "Rouster vtyd"
vty_must_contain "show interface"      "veth0"
vty_must_contain "show interface"      "192.0.2.1/24"
vty_must_contain "show ip interface veth0" "veth0"
vty_must_contain "show neighbor"       "192.0.2.9"
vty_must_contain "show neighbor 192.0.2.0/24" "192.0.2.9"
vty_must_contain "show vrf"            "vrf-blue"
vty_must_contain "show vrf"            "1001"
vty_must_contain "show ip route summary" "connected"
vty_must_contain "show ip route summary" "254"
vty_must_contain "show ip route summary" "vrf-blue"
vty_must_contain "show sav"            "savd"
vty_must_contain "show bfd summary"    "peers 1"
# The neighbour filter's honest empty (a wrong-family filter).
vty_must_contain "show neighbor 2001:db8:1::/48" "No neighbor matches"

echo "==> the rousterctl leg over the same live run dir"
ctl_must_contain "show interface"      "veth0"
ctl_must_contain "show interface veth1" "vrf-blue"
ctl_must_contain "show neighbour"      "192.0.2.9"
ctl_must_contain "show vrf"            "vrf-blue"
ctl_must_contain "show rib summary"    "1001"
ctl_must_contain "status"              "dump published"

# Liveness honesty: killing rousterd flips the views to the
# last-known-record footer and rousterctl's exit 4.
echo "==> liveness: SIGTERM rousterd; the dump becomes the last-known record"
docker exec "$NAME" sh -c 'kill -TERM "$(pidof rousterd)"'
wait_in_container "rousterd gone" 20 '! pidof rousterd >/dev/null'
if docker exec "$NAME" sh -c \
        "rousterctl --run-dir $RUN_DIR show vrf" >/dev/null 2>&1; then
    echo "FAIL: a dead-header-pid dump must exit 4" >&2
    exit 1
fi
docker exec "$NAME" sh -c \
    "vtyd --command 'show vrf' 2>&1" | grep -q "last-known record"
echo "    stale views render the record + name the dead pid"

echo "vty smoke test: PASS"
