#!/usr/bin/env bash
# W4B smoke test: live RTM_NEWLINK VRF enslavement in a resident rousterd.
#
# test-w4-vrf.sh pins the DUMP path (`--once`): VRF device and enslaved
# dummy are both in place before the daemon starts. This sibling pins the
# LIVE path: the daemon starts with the VRF device up but the dummy
# UNenslaved, and `ip link set dummy0 master vrf-test` after startup must
# arrive as a live LinkNew carrying the new master ifindex, visible in
# the generic dataplane-event line (the startup dump applies events
# without logging them, so the first `link new: dummy0` line in the log
# is this live event — asserted before the enslavement as an empty grep).
#
# Scenario (Docker container, statically linked musl binary built on the
# host — no build image needed):
#
#   - `ip link add vrf-test type vrf table 5001` + `ip link add dummy0
#     type dummy`, both UP, dummy0 NOT yet enslaved;
#   - resident rousterd's startup dump logs `vrf mirror vrf=vrf-test
#     ... table=5001 enslaved=0 routes=0` (baseline: memberless VRF);
#   - `ip link set dummy0 master vrf-test` then produces
#     `dataplane event other=link new: dummy0 (ifindex <D>, up, master
#     ifindex <V>) interfaces=...` with D/V read from `ip -o link show`
#     before the enslavement;
#   - kernel truth agrees (`ip -d link show dummy0` is a vrf slave).
#
# Base image: the FRR testbed (full iproute2 — busybox `ip`, the alpine
# default of the other smokes, has no `type vrf` link kind). Cached only;
# override with ROUSTER_TEST_BASE_IMAGE=... for another full-iproute2
# image.
#
#   scripts/test-w4b-vrf-live.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:w4b
NAME=rouster-w4b
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
LOG=/tmp/rousterd.log
CONF=/etc/rouster.conf
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_W4B_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/w4b-vrf-live}"

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

# Poll inside the container until a shell condition holds, or fail
# (test-w3-neighbours.sh convention).
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

echo "==> VRF device (table 5001) + UNenslaved dummy, both up"
docker exec "$NAME" ip link add vrf-test type vrf table 5001
docker exec "$NAME" ip link set vrf-test up
docker exec "$NAME" ip link add dummy0 type dummy
docker exec "$NAME" ip link set dummy0 up
VRF_IFINDEX="$(docker exec "$NAME" sh -c "ip -o link show vrf-test" | grep -oE '^[0-9]+')"
DUMMY_IFINDEX="$(docker exec "$NAME" sh -c "ip -o link show dummy0" | grep -oE '^[0-9]+')"
echo "    ifindex: vrf-test=$VRF_IFINDEX dummy0=$DUMMY_IFINDEX"

echo "==> writing config (one blackhole route)"
docker exec "$NAME" sh -c "printf '%s\n' \
  'ip route 198.51.100.0/24 blackhole' \
  > $CONF"

echo "==> starting resident rousterd"
docker exec -d "$NAME" sh -c "rousterd --config $CONF > $LOG 2>&1"

echo "==> baseline: VRF recognized with zero members; no live link events yet"
wait_in_container "vrf mirror baseline logged" 30 \
    "grep -q 'vrf mirror vrf=vrf-test ifindex=$VRF_IFINDEX table=5001 enslaved=0 routes=0' $LOG"
# The dump applies events silently, so no dummy0 link line may exist yet —
# whatever the next grep finds is the LIVE event.
docker exec "$NAME" sh -c "! grep -q 'link new: dummy0' $LOG"

echo "==> live enslavement: ip link set dummy0 master vrf-test"
docker exec "$NAME" ip link set dummy0 master vrf-test
wait_in_container "live LinkNew with new master logged" 20 \
    "grep -q 'dataplane event other=link new: dummy0 (ifindex $DUMMY_IFINDEX, up, master ifindex $VRF_IFINDEX) interfaces=' $LOG"

echo "==> kernel truth: dummy0 is a vrf-test slave"
docker exec "$NAME" sh -c "ip -d link show dummy0 | grep -q vrf_slave"

echo "w4b vrf live-event smoke test: PASS"
