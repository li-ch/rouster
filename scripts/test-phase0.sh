#!/usr/bin/env bash
# Phase 0 smoke test: rousterd programs static routes into the Linux kernel.
#
# The test itself needs only a Linux kernel — it runs in a Docker container
# (macOS Docker Desktop works) using a statically linked musl binary built on
# the host, so it does NOT require pulling a Rust build image from Docker Hub.
#
# Base image: override with ROUSTER_TEST_BASE_IMAGE if your registry access
# differs (default is a mirror already cached on this dev machine).
#
#   scripts/test-phase0.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:local
NAME=rouster-phase0
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-docker.m.daocloud.io/library/alpine:3.22}"

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
# Keep the container alive; rousterd runs inside via docker exec.
docker run -d --name "$NAME" --cap-add NET_ADMIN --entrypoint sh "$IMAGE" \
    -c 'while true; do sleep 3600; done' >/dev/null

GW="$(docker exec "$NAME" ip -4 route show default | awk '{print $3; exit}')"
echo "==> container default gateway: $GW"

echo "==> writing config"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 blackhole' \
  'ip route 203.0.113.0/24 $GW' \
  'ipv6 route 2001:db8:dead::/48 blackhole' \
  > /etc/rouster.conf"

echo "==> running rousterd --once"
docker exec "$NAME" rousterd --config /etc/rouster.conf --once

echo "==> verifying kernel routes"
docker exec "$NAME" ip -4 route show 198.51.100.0/24 | grep -q 'blackhole'
docker exec "$NAME" ip -4 route show 203.0.113.0/24 | grep -q "via $GW"
docker exec "$NAME" ip -6 route show 2001:db8:dead::/48 | grep -q 'blackhole'

echo "phase0 smoke test: PASS"
