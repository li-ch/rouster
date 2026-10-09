#!/usr/bin/env bash
# W3 smoke test: kernel neighbour (ARP/NDP) mirror in a resident rousterd.
#
# Verifies the three W3 behaviors against a live kernel (Docker container,
# statically linked musl binary built on the host — no build image needed):
#
#   (i)   the initial neighbour dump logs a count equal to
#         `ip neigh show | wc -l` in the container;
#   (ii)  neighbour add / replace each produce a NeighbourNew mirror
#         event and a "neighbour up" log line (ip + ifname + lladdr/state);
#   (iii) neighbour delete produces a NeighbourDel mirror event and a
#         "neighbour down" log line.
#
# Neighbours are programmed with the busybox `arp` applet (SIOCSARP/
# SIOCDARP): this alpine's `ip` supports `ip neigh show|flush` only, not
# add/replace/del. `ip neigh show` stays the read-side truth for (i).
#
# Base image override works the same as in test-p0a-reconcile.sh:
#   ROUSTER_TEST_BASE_IMAGE=... scripts/test-w3-neighbours.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:w3
NAME=rouster-w3
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

# Keep the neighbour table deterministic: v6 autoconf can seed entries.
docker exec "$NAME" sh -c \
    'sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true'

echo "==> seeding two permanent neighbours on a fresh /24 on eth0"
docker exec "$NAME" sh -c "ip addr add 192.0.2.1/24 dev eth0"
docker exec "$NAME" arp -s 192.0.2.11 02:00:00:00:00:11 -i eth0
docker exec "$NAME" arp -s 192.0.2.12 02:00:00:00:00:12 -i eth0

echo "==> writing config (one blackhole route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 blackhole' \
  > $CONF"

echo "==> starting resident rousterd"
docker exec -d "$NAME" sh -c "rousterd --config $CONF > $LOG 2>&1"
wait_in_container "initial neighbour mirror complete" 30 \
    "grep -q 'initial neighbour mirror' $LOG"

echo "==> (i) dump count matches ip neigh show"
MIRROR_COUNT="$(docker exec "$NAME" sh -c \
    "grep -o 'neighbours=[0-9]*' $LOG | tail -1 | cut -d= -f2")"
KERNEL_COUNT="$(docker exec "$NAME" sh -c 'ip neigh show | grep -c .')"
echo "    mirror=$MIRROR_COUNT kernel=$KERNEL_COUNT"
[ "$MIRROR_COUNT" = "$KERNEL_COUNT" ]

echo "==> (ii) add and replace produce neighbour up lines"
docker exec "$NAME" arp -s 192.0.2.99 02:00:00:00:00:99 -i eth0
wait_in_container "neighbour up logged for 192.0.2.99" 20 \
    "grep -q 'neighbour up neighbour=192\.0\.2\.99.*lladdr 02:00:00:00:00:99' $LOG"

docker exec "$NAME" arp -s 192.0.2.11 02:00:00:00:00:aa -i eth0
wait_in_container "replacement lladdr mirrored for 192.0.2.11" 20 \
    "grep -q 'neighbour up neighbour=192\.0\.2\.11.*lladdr 02:00:00:00:00:aa' $LOG"
wait_in_container "old lladdr gone from the mirror view" 20 \
    "! grep -q '192\.0\.2\.11.*lladdr 02:00:00:00:00:11' $LOG"

echo "==> (iii) delete produces a neighbour down line"
docker exec "$NAME" arp -d 192.0.2.12 -i eth0
wait_in_container "neighbour down logged for 192.0.2.12" 20 \
    "grep -q 'neighbour down neighbour=192\.0\.2\.12 ifname=eth0' $LOG"

echo "w3 neighbour smoke test: PASS"
