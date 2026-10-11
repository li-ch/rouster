#!/usr/bin/env bash
# N7 smoke test: the rpki RTR client against a REAL cache — gortr
# (gortr:local, v0.14.7) serving built-in-shape local data on RTR v1.
#
# This is a PROTOCOL interop proof, not a web-of-trust validation: the
# cache runs fully offline on an unsigned local JSON file
# (-verify=false -checktime=false); no TAL, no RRDP, no repository
# fetch. What it proves is the wire conversation: version-pinned
# negotiation (gortr closes silently on v2 — the N7 finding behind
# ClientConfig::max_version), a full refresh to Fresh, ROV verdicts
# over the loaded VRPs, Serial-Notify-driven incremental deltas
# (exact-tuple withdraw + announce), the Cache-Reset fallback after a
# cache restart, and the §6 expire flush after the cache dies with its
# port refusing connections.
#
# gortr:local is linux/amd64 under emulation on arm64 hosts — every
# wait below is a bounded poll loop, never a fixed sleep, with
# emulation margins.
#
# Legs:
#   1. full refresh + ROV  (Fresh, v1, sid 42, serial 0, 3 VRPs, six
#      pinned verdicts incl. the AS 0 disavowal and max-length rules)
#   2. incremental         (file swap + SIGHUP -> Serial Notify ->
#                           Serial Query -> delta -> Serial, serial 1)
#   3. cache reset         (container restart, fresh serial history ->
#                           Cache Reset -> Reset Query -> Fresh, serial 0)
#   4. death + expiry      (docker stop -> refused reconnects -> §6
#                           flush -> None)
#
#   scripts/test-rpki-gortr.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE="${ROUSTER_GORTR_IMAGE:-gortr:local}"
NAME=rouster-rpki-gortr
PORT="${ROUSTER_GORTR_PORT:-8282}"
SID=42
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_GORTR_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/n7}"
RTR_CHECK=target/debug/rtr-check
DATA=""
CAPTURES="$QUARANTINE/smoke"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    [ -n "$DATA" ] && rm -rf "$DATA"
}
trap cleanup EXIT

# Bounded poll: wait_for <seconds> <description> <command...>
wait_for() {
    local deadline=$((SECONDS + $1)) what="$2"
    shift 2
    while [ $SECONDS -lt $deadline ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 1
    done
    echo "FAIL: timed out waiting for: $what" >&2
    return 1
}

log() { echo "    $*"; }

mkdir -p "$CAPTURES"

# rpki-a.json: 3 ROAs (one AS 0 disavowal). rpki-b.json: the update —
# 198.51.100.0/24 gone, a v6 ROA in (content hash must change or
# gortr will not bump the serial).
DATA="$(mktemp -d /tmp/rouster-gortr.XXXXXX)"
cat > "$DATA/rpki-a.json" <<'EOF'
{"metadata":{"counts":3,"generated":1760000000,"valid":1900000000,"serial":1},"roas":[{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64512","ta":"n7"},{"prefix":"198.51.100.0/24","maxLength":25,"asn":"AS64513","ta":"n7"},{"prefix":"203.0.113.0/24","maxLength":24,"asn":"AS0","ta":"n7"}]}
EOF
cat > "$DATA/rpki-b.json" <<'EOF'
{"metadata":{"counts":3,"generated":1760000600,"valid":1900000600,"serial":2},"roas":[{"prefix":"192.0.2.0/24","maxLength":24,"asn":"AS64512","ta":"n7"},{"prefix":"203.0.113.0/24","maxLength":24,"asn":"AS0","ta":"n7"},{"prefix":"2001:db8::/32","maxLength":48,"asn":"AS64512","ta":"n7"}]}
EOF
cp "$DATA/rpki-a.json" "$DATA/rpki.json"

log "docker probe + rtr-check build"
docker image inspect "$IMAGE" >/dev/null
cargo build -p rpki --bin rtr-check

log "cache up ($IMAGE, sid $SID, RTR on 127.0.0.1:$PORT, refresh 10/retry 5/expire 30)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8282" -v "$DATA":/data:ro "$IMAGE" \
    -cache /data/rpki.json -verify=false -checktime=false \
    -rtr.sessionid "$SID" -rtr.refresh 10 -rtr.retry 5 -rtr.expire 30 \
    -refresh 5 -loglevel debug >/dev/null
# Readiness = the first successful file load ("New update"); a swap
# racing the entrypoint can fail the first read (gortr still starts —
# the -refresh timer retries and the line appears seconds later).
wait_for 90 "gortr first data load" \
    sh -c "docker logs $NAME 2>&1 | grep -q 'New update'"
docker logs "$NAME" > "$CAPTURES/gortr-startup.log" 2>&1

# ---- Leg 1: full refresh + ROV ----------------------------------------
log "leg 1: full refresh + ROV verdicts"
"$RTR_CHECK" --cache "127.0.0.1:$PORT" --max-version 1 --timeout 60 \
    --expect-state Fresh --expect-serial 0 --expect-vrps 3 \
    --expect-version 1 --expect-session-id "$SID" \
    --rov 192.0.2.0/24,64512,Valid \
    --rov 192.0.2.128/25,64512,Invalid \
    --rov 192.0.2.0/24,64513,Invalid \
    --rov 198.51.100.128/25,64513,Valid \
    --rov 203.0.113.0/24,64513,Invalid \
    --rov 8.8.8.0/24,15169,NotFound \
    > "$CAPTURES/leg1-rtr-check.log" 2>&1
log "leg 1 PASS (Fresh v1 sid=$SID serial=0 vrps=3; 6 ROV verdicts)"

# ---- Legs 2-4: one client process through update, reset, death -------
log "legs 2-4: one client session set (update -> restart -> death)"
LEG234="$CAPTURES/legs234-rtr-check.log"
"$RTR_CHECK" --cache "127.0.0.1:$PORT" --max-version 1 --timeout 150 \
    --expect-state None --expect-vrps 0 \
    > "$LEG234" 2>&1 &
RTPID=$!

wait_for 60 "initial Fresh@0" \
    grep -q "state=Fresh version=1 sid=$SID serial=0 vrps=3" "$LEG234"

# Leg 2: the data changes under the cache (tmp+rename so gortr's
# re-read never sees a half-written file), SIGHUP reloads now.
cp "$DATA/rpki-b.json" "$DATA/rpki.json.tmp"
mv "$DATA/rpki.json.tmp" "$DATA/rpki.json"
docker kill -s HUP "$NAME" >/dev/null
wait_for 60 "Serial Notify + delta -> Serial@1 vrps=3" \
    grep -q "state=Serial version=1 sid=$SID serial=1 vrps=3" "$LEG234"
log "leg 2 PASS (notify -> Serial Query -> exact-tuple delta, serial 1)"

# Leg 3: restart the cache — fresh serial history; the client's
# re-open (Serial Query for serial 1) is answered Cache Reset, the
# client falls back to a Reset Query and takes a full load.
docker restart "$NAME" >/dev/null
wait_for 90 "Cache Reset fallback -> Fresh@0 again" \
    sh -c "[ \$(grep -c 'state=Fresh version=1 sid=$SID serial=0 vrps=3' '$LEG234') -ge 2 ]"
log "leg 3 PASS (Cache Reset -> Reset Query -> full reload)"

# Leg 4: the cache dies with its port; refused reconnects never arm a
# session timer — the client must still honor the 30 s expire deadline
# and flush (state None), then exit cleanly.
docker stop "$NAME" >/dev/null
wait_for 120 "expire flush -> None + clean exit" \
    grep -q "rtr-check: PASS" "$LEG234"
wait "$RTPID"
log "leg 4 PASS (docker stop -> EOF -> §6 expire flush -> None)"

docker logs "$NAME" > "$CAPTURES/gortr-final.log" 2>&1 || true
log "clean disconnects on the cache side:"
grep -c "Disconnecting client" "$CAPTURES/gortr-final.log" \
    | xargs -I{} echo "    {} client disconnects logged by gortr"

echo "PASS: scripts/test-rpki-gortr.sh (captures in $CAPTURES)"
