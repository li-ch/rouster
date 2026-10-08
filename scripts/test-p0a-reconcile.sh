#!/usr/bin/env bash
# P0A smoke test: FIB reconciliation in a resident rousterd.
#
# Verifies the three P0A behaviors against a live kernel (Docker container,
# statically linked musl binary built on the host — no build image needed):
#
#   (i)   an externally added kernel-origin route appears in the mirror;
#   (ii)  an externally deleted rouster route is reinstalled by reconcile;
#   (iii) SIGHUP with a config missing the route withdraws it from the kernel.
#
# Base image override works the same as in test-phase0.sh:
#   ROUSTER_TEST_BASE_IMAGE=... scripts/test-p0a-reconcile.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:p0a
NAME=rouster-p0a
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-docker.m.daocloud.io/library/alpine:3.22}"
LOG=/var/log/rousterd.log
CONF=/etc/rouster.conf

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
    docker exec "$NAME" sh -c "tail -40 $LOG" >&2 || true
    return 1
}

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

echo "==> writing config (one blackhole route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 blackhole' \
  > $CONF"

echo "==> starting resident rousterd"
docker exec -d "$NAME" sh -c "rousterd --config $CONF > $LOG 2>&1"
wait_in_container "initial mirror complete" 30 "grep -q 'initial kernel route mirror' $LOG"

echo "==> (setup) rousterd installed the configured blackhole route"
docker exec "$NAME" ip route show 198.51.100.0/24 | grep -q blackhole

echo "==> (i) kernel-origin route add appears in the mirror"
docker exec "$NAME" ip route add 198.18.0.0/15 dev lo
wait_in_container "mirror picked up 198.18.0.0/15" 20 \
    "grep -q 'route new: 198.18.0.0/15' $LOG"

echo "==> (ii) externally deleted route is reinstalled by reconcile"
docker exec "$NAME" ip route del 198.51.100.0/24
wait_in_container "198.51.100.0/24 reinstalled" 50 \
    "ip route show 198.51.100.0/24 | grep -q blackhole"

echo "==> (iii) SIGHUP with config missing the route withdraws it"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 203.0.113.0/24 blackhole' \
  > $CONF"
docker exec "$NAME" sh -c 'kill -HUP "$(pidof rousterd)"'
wait_in_container "config reloaded" 20 "grep -q 'config reloaded' $LOG"
wait_in_container "198.51.100.0/24 withdrawn" 50 \
    'test -z "$(ip route show 198.51.100.0/24)"'
wait_in_container "replacement route installed" 50 \
    "ip route show 203.0.113.0/24 | grep -q blackhole"

echo "p0a reconcile smoke test: PASS"
