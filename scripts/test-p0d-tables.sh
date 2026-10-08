#!/usr/bin/env bash
# P0D smoke test: routing-table selection, including ids > 255 via RTA_TABLE.
#
# Scenario (Docker container, statically linked musl binary built on the
# host — no build image needed):
#
#   - dummy0 carries 192.0.2.1/24 so the gateway resolves;
#   - the config programs one route into table 1000 (`table <N>` keyword,
#     RTA_TABLE path — the 8-bit rtm_table header cannot address it) and
#     one into table 100 (header-only path);
#   - `ip route show table <N>` must contain each route, and the main
#     table (254) must NOT contain them.
#
# Base image override works the same as in test-phase0.sh:
#   ROUSTER_TEST_BASE_IMAGE=... scripts/test-p0d-tables.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:p0d
NAME=rouster-p0d
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

echo "==> gateway-carrying dummy interface"
docker exec "$NAME" ip link add dummy0 type dummy
docker exec "$NAME" ip link set dummy0 up
docker exec "$NAME" ip addr add 192.0.2.1/24 dev dummy0

echo "==> writing config (tables 1000 and 100)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 192.0.2.9 table 1000' \
  'ip route 203.0.113.0/24 192.0.2.9 table 100' \
  > $CONF"

echo "==> running rousterd --once"
docker exec "$NAME" rousterd --config "$CONF" --once

echo "==> verifying per-table programming"
docker exec "$NAME" ip route show table 1000 | grep -q '198.51.100.0/24'
docker exec "$NAME" ip route show table 1000 | grep -q 'via 192.0.2.9'
docker exec "$NAME" ip route show table 100 | grep -q '203.0.113.0/24'
# Neither route may leak into the main table.
docker exec "$NAME" sh -c \
    'test -z "$(ip route show table 254 198.51.100.0/24)" && test -z "$(ip route show table 254 203.0.113.0/24)"'

# Regression: no table keyword → main table, as before.
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 192.0.2.128/25 blackhole' \
  > $CONF"
docker exec "$NAME" rousterd --config "$CONF" --once
docker exec "$NAME" ip route show table 254 192.0.2.128/25 | grep -q blackhole

echo "p0d tables smoke test: PASS"
