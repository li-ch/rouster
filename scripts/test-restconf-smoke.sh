#!/usr/bin/env bash
# restconfd smoke test (S12-a M6; the S13-c v1.0 posture legs) — the
# RESTCONF-shaped northbound edge against a REAL daemon and a
# refusal stand-in, in containers:
#
#   restconfd (hand-rolled HTTP/1.1) ── GET/PUT/POST/DELETE ──> the
#   canonical file's YANG trees; accepted mutations run the configd
#   apply pipeline (render -> atomic write -> SIGHUP -> verify ->
#   auto-rollback).
#
# Frozen readouts (asserted via the daemons' published status files
# and the HTTP responses themselves — never log greps alone):
#   SOCKET    restconfd starts with NO plane flags and serves the
#             LOCAL UNIX SOCKET (the v1.0 default flip): the status
#             file says listener socket, the socket file's mode is
#             0660 (the filesystem permission IS the access
#             control), and TCP 8080 is NOT listening (the flip is
#             real, not additive).
#   TOKEN     the stanza's bearer token gates every request: no
#             Authorization header -> 401 + WWW-Authenticate:
#             Bearer (the RFC 8040 §7.1 error form, RFC 6241's
#             access-denied tag); a wrong token -> 401; the right
#             token -> 200. The dump NEVER carries the token
#             (write-only through the API).
#   TREE      GET /restconf/data (tokened, over the socket) carries
#             the bound trees in the dump shape (router-id, the
#             restconf member, savd); GET of a leaf answers the
#             wrapped member; an unknown path is the §7.1 error
#             form.
#   ACK       POST /restconf/data/savd/interface=veths2 (merge)
#             returns the per-daemon ack summary; the REAL savd
#             reloads at SIGHUP: `poll 2s interfaces 2` +
#             `installed 2 rules` in savd.status, pid UNCHANGED
#             (a reload, not a restart: invariant 2).
#   REFUSED   A validate-clean body the daemon REFUSES at load
#             (the stand-in savd's poison: poll 9 — the real savd
#             cannot refuse, its validate and load parsers are one
#             fn, disclosed): the PUT answers 409 with the
#             refused-the-reload + auto-rolled-back story, the
#             stand-in keeps its running word, the canonical holds
#             the staged bytes (the vtyd write-path precedent).
#   BACK      A bad body (poll 0) is a 400 and NOTHING moves; the
#             cleanup DELETE removes the staged poison and the
#             stand-in converges on the default poll.
#   TCP       The opt-in plane: restarted with --tcp, restconfd
#             serves 8080 (status: listener tcp), the token still
#             gates it (401 without, 200 with) — plain HTTP, the
#             disclosed posture.
#
# The scenario runs TWICE (fresh container each time —
# repeatability is part of the claim). Base image frr-testbed:10.2.2
# (cached only); the HTTP client is `restconf-probe` (busybox nc has
# no -U — the zapi-probe precedent: a real socket client built from
# the same tree, no curl in the image and none needed for a wire we
# own).
#
#   scripts/test-restconf-smoke.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:restconf
NAME=rouster-restconf
BASE_IMAGE="${ROUSTER_TEST_BASE_IMAGE:-frr-testbed:10.2.2}"
ROUSTERD_LOG=/var/log/rousterd.log
SAVD_LOG=/var/log/savd.log
RESTCONFD_LOG=/var/log/restconfd.log
ZAPI_SOCK=/run/rouster/zserv.api
CANONICAL=/root/rouster.conf
STATUS_FILE=/run/rouster/savd.status
RESTCONF_STATUS=/run/rouster/restconf.status
CONFIGD_STATUS=/run/rouster/configd.status
RESTCONF_SOCK=/run/rouster/restconf.sock
PORT=8080
# 64 hex chars = 256 bits (the bind gate floors tokens at 32).
TOKEN=4c1f0a9d3e7b2c845f6a1d09b3e72c5a8d4f0b6e9c2a7d3145e8b0f6c9a2d7e3
TOKEN_WRONG=0000000000000000000000000000000000000000000000000000000000000000
QUARANTINE="${ROUSTER_RESTCONF_QUARANTINE:-$SCRIPT_DIR/../../away/2026-10-14/quarantine/restconf}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

wait_in_container() { # <desc> <attempts> <body>
    local desc="$1" attempts="$2" body="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$NAME" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (waited $((attempts / 2))s)" >&2
    docker exec "$NAME" sh -c \
        "cat $STATUS_FILE $RESTCONF_STATUS $CONFIGD_STATUS 2>/dev/null; \
         echo '--- logs ---'; tail -5 $SAVD_LOG $RESTCONFD_LOG 2>/dev/null; \
         echo '--- canonical ---'; cat $CANONICAL 2>/dev/null; \
         echo '--- stand-in ---'; cat /var/log/standin-savd.log 2>/dev/null" 1>&2 || true
    return 1
}

# One HTTP exchange over restconf-probe (the socket plane by
# default; TOKEN rides --token — a client-side one-off, the probe's
# own help explains why that is fine for a client): <token> <method>
# <path> [body]
probe() {
    local token="$1" method="$2" path="$3" body="${4:-}"
    docker exec "$NAME" sh -c \
        "restconf-probe --socket $RESTCONF_SOCK --token '$token' '$method' '$path' '$body'"
}

# The tokened call (every functional leg uses this one).
http() { # <method> <path> [body]
    probe "$TOKEN" "$@"
}

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$NAME" sh -c "cat $CANONICAL" > "$QUARANTINE/rouster.conf" 2>&1 || true
    docker exec "$NAME" sh -c "cat $STATUS_FILE" > "$QUARANTINE/savd.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $RESTCONF_STATUS" > "$QUARANTINE/restconf.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $CONFIGD_STATUS" > "$QUARANTINE/configd.status" 2>&1 || true
    docker exec "$NAME" sh -c "cat $RESTCONFD_LOG $SAVD_LOG $ROUSTERD_LOG" \
        > "$QUARANTINE/logs.txt" 2>&1 || true
    docker exec "$NAME" sh -c "cat /etc/savd.conf" > "$QUARANTINE/savd.conf" 2>&1 || true
}

one_iteration() { # <n>
    local n="$1"
    echo "======== iteration $n ======"

    echo "==> [$n] starting container + topology (the configd smoke pattern)"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker run -d --name "$NAME" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --security-opt apparmor=unconfined \
        --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null
    docker exec "$NAME" mount -t proc none /proc
    docker exec "$NAME" ip link add veths1 type veth peer name veths2
    docker exec "$NAME" ip link set veths1 up
    docker exec "$NAME" ip link set veths2 up

    echo "==> [$n] baseline canonical + configd apply + the real daemons"
    docker exec "$NAME" sh -c "printf '%s\n' \
      'restconf {' \
      'port 8080' \
      'socket $RESTCONF_SOCK' \
      'token $TOKEN' \
      '}' \
      'daemon rousterd {' \
      '    zapi socket $ZAPI_SOCK' \
      '}' \
      'daemon savd {' \
      '    interface veths1' \
      '      mode strict' \
      '    poll 2' \
      '}' \
      > $CANONICAL"
    docker exec "$NAME" configd apply "$CANONICAL" >/dev/null
    docker exec -d "$NAME" sh -c "rousterd --config /etc/rouster.conf > $ROUSTERD_LOG 2>&1"
    docker exec -d "$NAME" sh -c "savd --config /etc/savd.conf --zapi-socket $ZAPI_SOCK > $SAVD_LOG 2>&1"
    wait_in_container "[$n] savd live on the baseline (poll 2s, 1 rule)" 40 \
        "grep -q 'poll 2s interfaces 1' $STATUS_FILE && grep -q '^installed 1 rules' $STATUS_FILE"
    local SAVD_PID
    SAVD_PID="$(docker exec "$NAME" cat /run/rouster/savd.pid)"

    echo "==> [$n] SOCKET: restconfd up with NO plane flags (the socket default)"
    docker exec -d "$NAME" sh -c \
        "restconfd --canonical $CANONICAL --run-dir /run/rouster --etc-dir /etc > $RESTCONFD_LOG 2>&1"
    wait_in_container "[$n] restconf.status published (listener socket)" 20 \
        "grep -q '^mode serve$' $RESTCONF_STATUS && grep -q '^listener socket$' $RESTCONF_STATUS && grep -q \"^socket $RESTCONF_SOCK\$\" $RESTCONF_STATUS"
    docker exec "$NAME" sh -c "[ \"\$(stat -c %a $RESTCONF_SOCK)\" = 660 ]" || {
        echo "FAIL: socket mode is not 0660: $(docker exec "$NAME" stat -c %a $RESTCONF_SOCK)"; return 1; }
    if docker exec "$NAME" sh -c "nc -z -w 1 127.0.0.1 $PORT" 2>/dev/null; then
        echo "FAIL: TCP $PORT is listening — the v1.0 default flip did not happen"; return 1
    fi
    echo "    the socket file is 0660; TCP 8080 is not listening (the flip is real)"

    echo "==> [$n] TOKEN: absent/wrong refused, right accepted"
    local resp
    resp="$(docker exec "$NAME" restconf-probe --socket $RESTCONF_SOCK GET /restconf/data/savd/poll)"
    grep -q 'HTTP/1.1 401' <<<"$resp" || { echo "FAIL: no-token not 401: $resp"; return 1; }
    grep -q 'WWW-Authenticate: Bearer' <<<"$resp" || { echo "FAIL: no challenge header: $resp"; return 1; }
    grep -q 'access-denied' <<<"$resp" || { echo "FAIL: no error form: $resp"; return 1; }
    resp="$(probe "$TOKEN_WRONG" GET /restconf/data/savd/poll)"
    grep -q 'HTTP/1.1 401' <<<"$resp" || { echo "FAIL: wrong token not 401: $resp"; return 1; }
    grep -q 'invalid bearer token' <<<"$resp" || { echo "FAIL: wrong token story: $resp"; return 1; }
    echo "    401 + WWW-Authenticate without/with a wrong token"

    echo "==> [$n] TREE: the dump shape over the socket (tokened)"
    resp="$(http GET /restconf/data)"
    grep -q 'HTTP/1.1 200' <<<"$resp" || { echo "FAIL: GET data not 200: $resp"; return 1; }
    grep -q '"savd"' <<<"$resp" || { echo "FAIL: no savd member: $resp"; return 1; }
    grep -q '"restconf":{"port":8080' <<<"$resp" || { echo "FAIL: no restconf member: $resp"; return 1; }
    grep -q "\"socket\":\"$RESTCONF_SOCK\"" <<<"$resp" || { echo "FAIL: no socket member: $resp"; return 1; }
    grep -q "$TOKEN" <<<"$resp" && { echo "FAIL: the token leaked into the dump: $resp"; return 1; }
    resp="$(http GET /restconf/data/savd/poll)"
    grep -q '{"poll":2}' <<<"$resp" || { echo "FAIL: leaf GET: $resp"; return 1; }
    resp="$(http GET /restconf/data/savd/nope)"
    grep -q 'HTTP/1.1 404' <<<"$resp" || { echo "FAIL: unknown path not 404: $resp"; return 1; }
    grep -q 'ietf-restconf:errors' <<<"$resp" || { echo "FAIL: no error form: $resp"; return 1; }
    echo "    GET answers the trees (tokened, over the socket); the token is nowhere in the dump"

    echo "==> [$n] ACK: POST merges a stanza, the real savd confirms the reload"
    resp="$(http POST /restconf/data/savd/interface=veths2 '{"mode":"strict"}')"
    grep -q 'HTTP/1.1 200' <<<"$resp" || { echo "FAIL: POST not 200: $resp"; return 1; }
    grep -q '"daemon":"savd"' <<<"$resp" || { echo "FAIL: no ack summary: $resp"; return 1; }
    grep -q '"result":"signaled"' <<<"$resp" || { echo "FAIL: not signaled: $resp"; return 1; }
    grep -q '"ack":"confirmed"' <<<"$resp" || { echo "FAIL: not confirmed: $resp"; return 1; }
    wait_in_container "[$n] savd reloaded: poll 2s, 2 rules" 40 \
        "grep -q 'poll 2s interfaces 2' $STATUS_FILE && grep -q '^installed 2 rules' $STATUS_FILE"
    [ "$(docker exec "$NAME" cat /run/rouster/savd.pid)" = "$SAVD_PID" ] || {
        echo "FAIL: savd restarted (pid moved)"; return 1; }
    echo "    POST -> apply -> SIGHUP -> savd.status flipped, pid unchanged"

    echo "==> [$n] REFUSED (400 leg): a bad body moves nothing"
    resp="$(http PUT /restconf/data/savd/poll '0')"
    grep -q 'HTTP/1.1 400' <<<"$resp" || { echo "FAIL: bad PUT not 400: $resp"; return 1; }
    grep -q 'error-tag' <<<"$resp" || { echo "FAIL: no error form: $resp"; return 1; }
    docker exec "$NAME" sh -c "grep -q 'poll 2' /etc/savd.conf" || {
        echo "FAIL: rendered file moved on a refused body"; return 1; }
    echo "    poll 0 refused with the error form; nothing written"

    echo "==> [$n] REFUSED (load leg): the daemon refuses, auto-rollback answers 409"
    # The real savd cannot refuse a validated config (one parser fn,
    # disclosed) — the stand-in provides the refusal window: it owns
    # savd.pid, publishes the same config projection the real savd
    # does, and refuses any load whose poll is 9 (validate-clean,
    # load-poison), keeping and republishing its running word.
    docker exec "$NAME" sh -c 'kill -TERM "$(pidof savd)" 2>/dev/null'
    wait_in_container "[$n] real savd fully exited" 20 '! pidof savd >/dev/null'
    docker exec "$NAME" sh -c "cat > /root/standin-savd.sh <<'EOS'
#!/bin/sh
echo \$\$ > /run/rouster/savd.pid
CONF=/etc/savd.conf
STATUS=/run/rouster/savd.status
publish() {
  poll=\$(grep -E '(^|[[:space:]])poll ' \"\$CONF\" | head -1 | awk '{print \$NF}'); poll=\${poll:-5}
  ifc=\$(grep -cE '(^|[[:space:]])interface ' \"\$CONF\" 2>/dev/null); ifc=\${ifc:-0}
  printf 'savd 0.0.0 pid %s\nconfig mode strict-uRPF action monitor poll %ss interfaces %s bindings 0 collision ignore hysteresis 3s backend rp_filter\n' \$\$ \"\$poll\" \"\$ifc\" > \"\$STATUS\"
}
onhup() {
  if grep -qE '(^|[[:space:]])poll 9([[:space:]]|\$)' \"\$CONF\" 2>/dev/null; then
    sleep 0.3; touch \"\$STATUS\"   # refused: republish the running word
  else
    publish
  fi
}
trap onhup HUP
publish
while :; do sleep 0.2; done
EOS
chmod +x /root/standin-savd.sh"
    docker exec -d "$NAME" sh -c "/root/standin-savd.sh > /var/log/standin-savd.log 2>&1"
    wait_in_container "[$n] stand-in savd published its word" 20 \
        "grep -q 'poll 2s interfaces 2' $STATUS_FILE"
    resp="$(http PUT /restconf/data/savd/poll '9')"
    grep -q 'HTTP/1.1 409' <<<"$resp" || { echo "FAIL: refused load not 409: $resp"; return 1; }
    grep -q 'refused the reload' <<<"$resp" || { echo "FAIL: refusal not surfaced: $resp"; return 1; }
    grep -q 'auto-rolled back' <<<"$resp" || { echo "FAIL: no auto-rollback story: $resp"; return 1; }
    wait_in_container "[$n] stand-in kept its running word" 20 \
        "grep -q 'poll 2s interfaces 2' $STATUS_FILE"
    docker exec "$NAME" sh -c "grep -q 'poll 9' $CANONICAL" || {
        echo "FAIL: canonical does not hold the staged bytes"; return 1; }
    echo "    409 + auto-rollback; the daemon kept its word; the canonical holds the staged bytes"

    echo "==> [$n] BACK: the cleanup DELETE converges the daemon"
    resp="$(http DELETE /restconf/data/savd/poll)"
    grep -q 'HTTP/1.1 200' <<<"$resp" || { echo "FAIL: DELETE not 200: $resp"; return 1; }
    wait_in_container "[$n] stand-in converged on the default poll" 20 \
        "grep -q 'poll 5s interfaces 2' $STATUS_FILE"
    echo "    DELETE removed the staged poison; savd runs the default poll"

    echo "==> [$n] TCP: the opt-in plane still answers (tokened)"
    docker exec "$NAME" sh -c 'kill -TERM "$(pidof restconfd)" 2>/dev/null'
    # The clean-exit contract (the savd discipline): BOTH files go.
    # (Not pidof: the docker-exec reparenting makes process-reaping
    # timing unfalsifiable from outside; the file clear is the
    # documented observable.)
    wait_in_container "[$n] socket-mode restconfd exited (socket + status cleared)" 30 \
        "! test -e $RESTCONF_SOCK && ! test -e $RESTCONF_STATUS"
    docker exec -d "$NAME" sh -c \
        "restconfd --canonical $CANONICAL --run-dir /run/rouster --etc-dir /etc --tcp > $RESTCONFD_LOG 2>&1"
    wait_in_container "[$n] restconf.status published (listener tcp, port 8080)" 20 \
        "grep -q '^listener tcp$' $RESTCONF_STATUS && grep -q '^port 8080$' $RESTCONF_STATUS"
    resp="$(docker exec "$NAME" restconf-probe --host 127.0.0.1 --port $PORT GET /restconf/data/savd/poll)"
    grep -q 'HTTP/1.1 401' <<<"$resp" || { echo "FAIL: TCP no-token not 401: $resp"; return 1; }
    resp="$(docker exec "$NAME" restconf-probe --host 127.0.0.1 --port $PORT --token "$TOKEN" GET /restconf/data/savd/poll)"
    grep -q '{"poll":5}' <<<"$resp" || { echo "FAIL: TCP tokened GET: $resp"; return 1; }
    echo "    --tcp arms 8080; the token gates the TCP plane too (the default poll rides from BACK)"
}

echo "==> building rousterd + savd + configd + restconfd + restconf-probe ($MUSL_TARGET, release)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd
cargo build --release --target "$MUSL_TARGET" -p sav --bin savd
cargo build --release --target "$MUSL_TARGET" -p configd --bin configd
cargo build --release --target "$MUSL_TARGET" -p configd --bin restconfd
cargo build --release --target "$MUSL_TARGET" -p configd --bin restconf-probe

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; \
      docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/rousterd" "$BUILD_DIR/rousterd"
cp "target/$MUSL_TARGET/release/savd" "$BUILD_DIR/savd"
cp "target/$MUSL_TARGET/release/configd" "$BUILD_DIR/configd"
cp "target/$MUSL_TARGET/release/restconfd" "$BUILD_DIR/restconfd"
cp "target/$MUSL_TARGET/release/restconf-probe" "$BUILD_DIR/restconf-probe"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY rousterd /usr/local/bin/rousterd
COPY savd /usr/local/bin/savd
COPY configd /usr/local/bin/configd
COPY restconfd /usr/local/bin/restconfd
COPY restconf-probe /usr/local/bin/restconf-probe
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

one_iteration 1
one_iteration 2
capture
echo "restconf smoke: PASS x2 (socket default 0660 + no-TCP + token 401s + tree GET + real-savd ack + 409 auto-rollback + DELETE back + TCP opt-in, status-file asserted)"
