#!/usr/bin/env bash
# Z4 smoke test: staticd installs routes into a resident rousterd over ZAPI.
#
# Rousterd runs resident with a `zapi socket` line and an EMPTY route config;
# staticd (a separate binary, the FRR shape) holds the actual routes and
# speaks ZAPI to it. The test proves the canonical Z4 path against a live
# kernel:
#
#   (i)   the blackhole route lands in `ip route` WITHOUT rousterd ever
#         parsing it (rousterd log: "loaded static routes count=0");
#   (ii)  the route arrived via ZAPI ("zapi: session established" +
#         "zapi: route add" in the rousterd log);
#   (iii) SIGHUP to staticd with the route removed withdraws it from the
#         kernel (staticd-side diff, ROUTE_DELETE over ZAPI).
#
# Same build/runner shape as test-p0a-reconcile.sh (host musl build, alpine
# container). Base image override:
#   ROUSTER_TEST_BASE_IMAGE=... scripts/test-z4-staticd.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:z4
NAME=rouster-z4
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-docker.m.daocloud.io/library/alpine:3.22}"
ROUSTERD_LOG=/var/log/rousterd.log
STATICD_LOG=/var/log/staticd.log
ROUSTERD_CONF=/etc/rouster.conf
STATICD_CONF=/etc/staticd.conf
ZAPI_SOCK=/run/rouster/zserv.api

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
    docker exec "$NAME" sh -c "tail -40 $ROUSTERD_LOG; tail -40 $STATICD_LOG" >&2 || true
    return 1
}

# Assert a string in a daemon log; tracing emits ANSI escapes into files, so
# strip them before grepping (busybox sed handles \x1b fine).
log_grep() {
    docker exec "$NAME" sh -c "sed 's/\x1b\[[0-9;]*m//g' $1 | grep -q '$2'"
}

echo "==> building rousterd + staticd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin staticd

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cp "target/$MUSL_TARGET/release/staticd" "$BUILD_DIR/staticd"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
COPY staticd /usr/local/bin/staticd
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME"
docker run -d --name "$NAME" --cap-add NET_ADMIN --entrypoint sh "$IMAGE" \
    -c 'while true; do sleep 3600; done' >/dev/null

echo "==> writing configs (rousterd: ZAPI socket only; staticd: one blackhole route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  > $ROUSTERD_CONF"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 blackhole' \
  > $STATICD_CONF"

echo "==> starting resident rousterd (no routes of its own)"
docker exec -d "$NAME" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd zapi server up" 30 "sed 's/\x1b\[[0-9;]*m//g' $ROUSTERD_LOG | grep -q 'zapi: listening'"

echo "==> starting staticd against the zapi socket"
docker exec -d "$NAME" sh -c "staticd --config $STATICD_CONF --zapi-socket $ZAPI_SOCK > $STATICD_LOG 2>&1"

echo "==> (i) route lands in the kernel FIB without rousterd parsing it"
wait_in_container "blackhole route installed" 40 \
    "ip route show 198.51.100.0/24 | grep -q blackhole"
log_grep "$ROUSTERD_LOG" "loaded static routes count=0" \
    || { echo "FAIL: rousterd parsed static routes itself" >&2; exit 1; }

echo "==> (ii) the route arrived over ZAPI"
log_grep "$ROUSTERD_LOG" "zapi: session established" \
    && log_grep "$ROUSTERD_LOG" "zapi: route add" \
    || { echo "FAIL: no ZAPI route add in rousterd log" >&2; exit 1; }

echo "==> (iii) SIGHUP to staticd with the route removed withdraws it"
docker exec "$NAME" sh -c ": > $STATICD_CONF"
docker exec "$NAME" sh -c 'kill -HUP "$(pidof staticd)"'
wait_in_container "route withdrawn" 40 \
    'test -z "$(ip route show 198.51.100.0/24)"'

echo "z4 staticd smoke test: PASS"
