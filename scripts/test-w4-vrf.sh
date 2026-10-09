#!/usr/bin/env bash
# W4 smoke test: VRF (device + table) awareness in the netlink mirror.
#
# Scenario (Docker container, statically linked musl binary built on the
# host — no build image needed):
#
#   - `ip link add vrf-test type vrf table 5001` + one enslaved dummy
#     (dummy0, 192.0.2.1/24) + one boot-origin route seeded into table
#     5001 by `ip route add`;
#   - rousterd --once must:
#       (i)   recognize the VRF device — a `vrf mirror` log line with
#             vrf=vrf-test, its table (5001) and enslaved count;
#       (ii)  mirror the kernel-origin routes of table 5001 — the line's
#             route count equals `ip route show table 5001` BEFORE the
#             daemon runs (connected + local + broadcast + seeded);
#       (iii) program a `table 5001` static route back into that table
#             (`ip route show table 5001` shows it, table 254 does not).
#
# Base image: the FRR testbed (full iproute2 — busybox `ip`, the alpine
# default of the other smokes, has no `type vrf` link kind). Cached only;
# override with ROUSTER_TEST_BASE_IMAGE=... for another full-iproute2
# image.
#
#   scripts/test-w4-vrf.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:w4
NAME=rouster-w4
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
LOG=/tmp/rousterd.log
CONF=/etc/rouster.conf
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_W4_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/w4-vrf}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

capture() {
    mkdir -p "$QUARANTINE"
    docker cp "$NAME:$LOG" "$QUARANTINE/rousterd.log" 2>/dev/null || true
    docker exec "$NAME" sh -c \
        'ip -d link show vrf-test; ip -d link show dummy0; echo ---; ip route show table 5001; echo ---; ip route show table 254' \
        > "$QUARANTINE/routes-and-links.txt" 2>&1 || true
}

echo "==> building rousterd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
ENTRYPOINT ["rousterd"]
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME"
# The testbed image's own entrypoint (FRR init) is replaced by a sleep
# loop; the daemon runs via docker exec below.
docker run -d --name "$NAME" --cap-add NET_ADMIN --entrypoint sh "$IMAGE" \
    -c 'while true; do sleep 3600; done' >/dev/null

echo "==> VRF device (table 5001) + enslaved dummy + seeded table-5001 route"
docker exec "$NAME" ip link add vrf-test type vrf table 5001
docker exec "$NAME" ip link set vrf-test up
docker exec "$NAME" ip link add dummy0 type dummy
docker exec "$NAME" ip link set dummy0 master vrf-test
docker exec "$NAME" ip link set dummy0 up
docker exec "$NAME" ip addr add 192.0.2.1/24 dev dummy0
# Boot-origin (administrative) route inside the VRF table: mirror input.
docker exec "$NAME" ip route add 10.9.0.0/16 dev dummy0 table 5001
# Kernel-side truth of table 5001 across BOTH address families: the mirror
# is AF-agnostic, and the VRF table holds the dummy's v6 link-local and
# multicast routes next to the v4 ones (sysctl is read-only here, so v6
# cannot be disabled — W3's alpine trick does not carry over).
KERNEL_V4="$(docker exec "$NAME" sh -c 'ip route show table 5001 | grep -c .')"
KERNEL_V6="$(docker exec "$NAME" sh -c 'ip -6 route show table 5001 | grep -c .')"
KERNEL_BEFORE=$((KERNEL_V4 + KERNEL_V6))
echo "    table 5001 before rousterd: $KERNEL_BEFORE routes (v4=$KERNEL_V4 v6=$KERNEL_V6)"

echo "==> writing config (one static route into the VRF table)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 203.0.113.0/24 192.0.2.9 table 5001' \
  > $CONF"

echo "==> running rousterd --once"
docker exec "$NAME" sh -c "rousterd --config $CONF --once > $LOG 2>&1"

echo "==> (i)+(ii) VRF device recognized; table-5001 mirror count matches kernel"
docker exec "$NAME" sh -c \
    "grep -q 'vrf mirror vrf=vrf-test ifindex=[0-9]* table=5001 enslaved=1 routes=' $LOG"
MIRROR_COUNT="$(docker exec "$NAME" sh -c \
    "grep -o 'vrf mirror vrf=vrf-test.*routes=[0-9]*' $LOG | grep -o 'routes=[0-9]*' | cut -d= -f2")"
echo "    mirror=$MIRROR_COUNT kernel=$KERNEL_BEFORE"
[ "$MIRROR_COUNT" = "$KERNEL_BEFORE" ]

echo "==> (iii) static route programmed back into table 5001"
docker exec "$NAME" ip route show table 5001 203.0.113.0/24 | grep -q 'via 192.0.2.9'
# The seeded kernel route is untouched, and nothing leaks into main (254).
docker exec "$NAME" ip route show table 5001 10.9.0.0/16 | grep -q 'dev dummy0'
docker exec "$NAME" sh -c \
    'test -z "$(ip route show table 254 203.0.113.0/24)"'

# Regression (P0D): without `table <N>` the route lands in main, as before.
echo "==> regression: no table keyword -> main table"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 192.0.2.128/25 blackhole' \
  > $CONF"
docker exec "$NAME" sh -c "rousterd --config $CONF --once >> $LOG 2>&1"
docker exec "$NAME" ip route show table 254 192.0.2.128/25 | grep -q blackhole

echo "w4 vrf smoke test: PASS"
