#!/usr/bin/env bash
# P0C smoke test: ECMP routes reach the kernel as full nexthop groups
# (RTA_MULTIPATH).
#
# Scenario (Docker container, statically linked musl binary built on the
# host — no build image needed):
#
#   - dummy0 carries two gateway addresses in the same subnet
#     (192.0.2.1/24 and 192.0.2.2/24);
#   - the config programs `ip route 198.51.100.0/24 192.0.2.1 192.0.2.2`;
#   - `ip route show` must list BOTH nexthops for the prefix.
#
# Base image override works the same as in test-phase0.sh:
#   ROUSTER_TEST_BASE_IMAGE=... scripts/test-p0c-ecmp.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:p0c
NAME=rouster-p0c
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-docker.m.daocloud.io/library/alpine:3.22}"
CONF=/etc/rouster.conf

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

echo "==> building rousterd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
ENTRYPOINT ["rousterd"]
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME"
docker run -d --name "$NAME" --cap-add NET_ADMIN --entrypoint sh "$IMAGE" \
    -c 'while true; do sleep 3600; done' >/dev/null

echo "==> two dummy-attached gateway addresses in one subnet"
docker exec "$NAME" ip link add dummy0 type dummy
docker exec "$NAME" ip link set dummy0 up
docker exec "$NAME" ip addr add 192.0.2.1/24 dev dummy0
docker exec "$NAME" ip addr add 192.0.2.2/24 dev dummy0

echo "==> writing config (two-gateway ECMP route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 192.0.2.1 192.0.2.2' \
  > $CONF"

echo "==> running rousterd --once"
docker exec "$NAME" rousterd --config "$CONF" --once

echo "==> verifying both nexthops are programmed"
# A multipath route prints one `nexthop ...` line per member; exactly two
# are expected, both on dummy0.
NEXTHOPS="$(docker exec "$NAME" ip route show 198.51.100.0/24)"
echo "$NEXTHOPS"
COUNT="$(echo "$NEXTHOPS" | grep -c nexthop)"
[ "$COUNT" -eq 2 ] || {
    echo "FAIL: expected 2 nexthops, got $COUNT" >&2
    exit 1
}
echo "$NEXTHOPS" | grep -q 'via 192.0.2.1 dev dummy0'
echo "$NEXTHOPS" | grep -q 'via 192.0.2.2 dev dummy0'

# Regression: single-gateway and blackhole lines still program directly.
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 192.0.2.1 192.0.2.2' \
  'ip route 203.0.113.0/24 192.0.2.9' \
  'ip route 192.0.2.128/25 blackhole' \
  > $CONF"
docker exec "$NAME" rousterd --config "$CONF" --once
docker exec "$NAME" ip route show 203.0.113.0/24 | grep -q 'via 192.0.2.9'
docker exec "$NAME" ip route show 192.0.2.128/25 | grep -q blackhole

echo "p0c ecmp smoke test: PASS"
