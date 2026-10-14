#!/usr/bin/env bash
# configd smoke test (Phase 4, S7-c M4) — the transactional config
# manager against REAL daemons, in one container:
#
#   configd apply ──render──> /etc/{rouster,savd,bfdd}.conf
#        │                        (read at SIGHUP by the running daemons)
#        └──SIGHUP──> rousterd (pid: rousterd.status header)
#                     savd   (pidfile)      ──> savd.status CHANGES
#                     bfdd   (pidfile)      ──> bfdd.status CHANGES
#
# Frozen readouts (asserted via the daemons' published status files —
# the run-dir contract, never log greps alone):
#   APPLY-1   the canonical v1 renders the per-daemon files and
#             records generation 1 while nothing is running yet
#             (not-running outcomes — the files are in place for the
#             starts that follow).
#   APPLY-2   a CHANGED canonical (savd poll 2 -> 3, a second
#             interface stanza, a second bfdd peer) is applied by
#             ONE configd invocation: savd's status flips to
#             `poll 3s`, `interfaces 2`, `installed 2 rules`;
#             bfdd's to `peers 2` + two session lines — and the
#             savd PID IS UNCHANGED (a reload, not a restart:
#             invariant 2). configd.status holds generation 2 with
#             per-daemon `result signaled`.
#   ROLLBACK  `configd rollback` re-applies the previous generation:
#             savd back to `poll 2s` / 1 rule, bfdd back to 1 peer,
#             generation 3 recorded (history never rewritten).
#
# Topology: one veth pair (veths1/veths2) — savd's rule count is
# stanza-driven (only configured interfaces generate rules), so
# stanza veths1 -> 1 rule, + stanza veths2 -> 2 rules, deterministic
# regardless of eth0/lo. /proc/sys overmounted (the w8 pattern) so
# the strict rp_filter install works. Caps NET_ADMIN+NET_RAW+
# SYS_ADMIN, no --privileged. Base image frr-testbed:10.2.2
# (cached only).
#
#   scripts/test-configd-smoke.sh
set -euo pipefail

# Resolve the script dir to an ABSOLUTE path before any cd (the
# quarantine default anchors on it).
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:configd
NAME=rouster-configd
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
ROUSTERD_LOG=/var/log/rousterd.log
SAVD_LOG=/var/log/savd.log
BFDD_LOG=/var/log/bfdd.log
ZAPI_SOCK=/run/rouster/zserv.api
CANONICAL=/root/rouster.conf
STATUS_FILE=/run/rouster/savd.status
BFDD_STATUS=/run/rouster/bfdd.status
CONFIGD_STATUS=/run/rouster/configd.status
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_CONFIGD_QUARANTINE:-$SCRIPT_DIR/../../away/2026-10-14/quarantine/configd}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# Poll inside the container until a shell condition holds, or fail.
wait_in_container() { # <desc> <attempts> <body>
    local desc="$1" attempts="$2" body="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$NAME" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (waited $((attempts / 2))s)" >&2
    docker exec "$NAME" sh -c "cat $SAVD_LOG $BFDD_LOG $CONFIGD_STATUS" 1>&2 || true
    exit 1
}

# The canonical v1: one stanza (veths1), poll 2, one bfdd peer.
write_canonical_v1() {
    docker exec "$NAME" sh -c "printf '%s\n' \
      'router-id 198.51.100.1' \
      'daemon rousterd {' \
      '    zapi socket $ZAPI_SOCK' \
      '}' \
      'daemon savd {' \
      '    interface veths1' \
      '      mode strict' \
      '    poll 2' \
      '}' \
      'daemon bfdd {' \
      '    peer 192.0.2.9' \
      '      transmit-interval 300' \
      '}' \
      > $CANONICAL"
}

# The canonical v2: poll 3, a second stanza (veths2), a second peer.
write_canonical_v2() {
    docker exec "$NAME" sh -c "printf '%s\n' \
      'router-id 198.51.100.1' \
      'daemon rousterd {' \
      '    zapi socket $ZAPI_SOCK' \
      '}' \
      'daemon savd {' \
      '    interface veths1' \
      '      mode strict' \
      '    interface veths2' \
      '      mode strict' \
      '    poll 3' \
      '}' \
      'daemon bfdd {' \
      '    peer 192.0.2.9' \
      '      transmit-interval 300' \
      '    peer 198.51.100.9' \
      '}' \
      > $CANONICAL"
}

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$NAME" sh -c "cat $CONFIGD_STATUS" > "$QUARANTINE/configd.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $STATUS_FILE" > "$QUARANTINE/savd.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $BFDD_STATUS" > "$QUARANTINE/bfdd.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $SAVD_LOG" > "$QUARANTINE/savd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat $BFDD_LOG" > "$QUARANTINE/bfdd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat $ROUSTERD_LOG" > "$QUARANTINE/rousterd.log" 2>&1 || true
    docker exec "$NAME" sh -c "cat /etc/rouster.conf /etc/savd.conf /etc/bfdd.conf" \
        > "$QUARANTINE/rendered-confs.txt" 2>&1 || true
}

echo "==> building rousterd + savd + bfdd + configd ($MUSL_TARGET, release)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd
cargo build --release --target "$MUSL_TARGET" -p sav --bin savd
cargo build --release --target "$MUSL_TARGET" -p bfdd --bin bfdd
cargo build --release --target "$MUSL_TARGET" -p configd --bin configd

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; \
      docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cp "target/$MUSL_TARGET/release/savd" "$BUILD_DIR/savd"
cp "target/$MUSL_TARGET/release/bfdd" "$BUILD_DIR/bfdd"
cp "target/$MUSL_TARGET/release/configd" "$BUILD_DIR/configd"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
COPY savd /usr/local/bin/savd
COPY bfdd /usr/local/bin/bfdd
COPY configd /usr/local/bin/configd
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME (w8 cap pattern)"
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

echo "==> making /proc/sys writable (fresh procfs overmount; the w8 pattern)"
docker exec "$NAME" mount -t proc none /proc

echo "==> topology: one veth pair (stanza-driven rule counts)"
docker exec "$NAME" ip link add veths1 type veth peer name veths2
docker exec "$NAME" ip addr add 198.51.100.1/24 dev veths1
docker exec "$NAME" ip addr add 192.0.2.1/24 dev veths2
docker exec "$NAME" ip link set veths1 up
docker exec "$NAME" ip link set veths2 up

echo "==> [APPLY-1] canonical v1 applied while nothing runs"
write_canonical_v1
docker exec "$NAME" configd apply "$CANONICAL"
# Generation 1, and every daemon honestly `not-running` (the files
# are in place for the starts that follow).
docker exec "$NAME" sh -c "grep -q '^generation 1 ' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q 'daemon savd .*result not-running' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q 'daemon rousterd .*result not-running' $CONFIGD_STATUS"
# The rendered files carry exactly the section bodies.
docker exec "$NAME" sh -c "grep -q 'zapi socket $ZAPI_SOCK' /etc/rouster.conf"
docker exec "$NAME" sh -c "grep -q 'poll 2' /etc/savd.conf"
docker exec "$NAME" sh -c "grep -q 'peer 192.0.2.9' /etc/bfdd.conf"
docker exec "$NAME" sh -c "grep -q '^router-id 198.51.100.1$' $CONFIGD_STATUS"
docker exec "$NAME" ls /run/rouster/configd/generations/ | grep -q '^000001-'
echo "    rendered + generation 1 recorded, nothing running"

echo "==> starting the daemons from the rendered files"
docker exec -d "$NAME" sh -c "rousterd --config /etc/rouster.conf > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd zapi server up" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
docker exec -d "$NAME" sh -c "savd --config /etc/savd.conf --zapi-socket $ZAPI_SOCK > $SAVD_LOG 2>&1"
docker exec -d "$NAME" sh -c "bfdd --config /etc/bfdd.conf > $BFDD_LOG 2>&1"

# v1 behavior, asserted from the status files.
wait_in_container "savd status: poll 2s, 1 stanza, 1 rule" 40 \
    "grep -q 'poll 2s interfaces 1' $STATUS_FILE && grep -q '^installed 1 rules' $STATUS_FILE"
wait_in_container "bfdd status: 1 peer" 30 "grep -q '^peers 1$' $BFDD_STATUS"
# (No sysctl leg by design: monitor action + the rp_filter backend
# installs nothing kernel-side — "no kernel rule installed (rp_filter
# has no count-only mode)" — so the status files ARE the behavior
# surface, exactly what this smoke pins.)
SAVD_PID_BEFORE="$(docker exec "$NAME" cat /run/rouster/savd.pid)"
BFDD_PID_BEFORE="$(docker exec "$NAME" cat /run/rouster/bfdd.pid)"
echo "    v1 live: savd 1 rule + poll 2s, bfdd 1 peer, savd pid $SAVD_PID_BEFORE"

echo "==> [APPLY-2] one configd apply flips the live behavior"
write_canonical_v2
docker exec "$NAME" configd apply "$CANONICAL"
docker exec "$NAME" sh -c "grep -q '^generation 2 ' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q 'daemon savd .*result signaled' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q 'daemon rousterd .*result signaled' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q 'daemon bfdd .*result signaled' $CONFIGD_STATUS"
# THE behavior change, from the daemons' own published status.
wait_in_container "savd reloaded: poll 3s, 2 stanzas, 2 rules" 40 \
    "grep -q 'poll 3s interfaces 2' $STATUS_FILE && grep -q '^installed 2 rules' $STATUS_FILE"
wait_in_container "bfdd reloaded: 2 peers" 30 \
    "grep -q '^peers 2$' $BFDD_STATUS"
[ "$(docker exec "$NAME" sh -c "grep -c '^session ' $BFDD_STATUS")" = 2 ]
# A reload, not a restart (invariant 2): same pids across the SIGHUP.
[ "$(docker exec "$NAME" cat /run/rouster/savd.pid)" = "$SAVD_PID_BEFORE" ]
[ "$(docker exec "$NAME" cat /run/rouster/bfdd.pid)" = "$BFDD_PID_BEFORE" ]
echo "    v2 live via SIGHUP: savd poll 3s / 2 rules, bfdd 2 peers, pids unchanged"

echo "==> [ROLLBACK] the previous generation re-applied"
docker exec "$NAME" configd rollback
docker exec "$NAME" sh -c "grep -q '^generation 3 ' $CONFIGD_STATUS"
docker exec "$NAME" sh -c "grep -q '^source rollback of generation 1$' $CONFIGD_STATUS"
wait_in_container "savd rolled back: poll 2s, 1 stanza, 1 rule" 40 \
    "grep -q 'poll 2s interfaces 1' $STATUS_FILE && grep -q '^installed 1 rules' $STATUS_FILE"
wait_in_container "bfdd rolled back: 1 peer" 30 "grep -q '^peers 1$' $BFDD_STATUS"
[ "$(docker exec "$NAME" cat /run/rouster/savd.pid)" = "$SAVD_PID_BEFORE" ]
echo "    rolled back to v1 behavior, generation 3, still no restart"

capture
echo "configd smoke: PASS (apply x2 + rollback, status-file asserted)"
