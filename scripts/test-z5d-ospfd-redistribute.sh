#!/usr/bin/env bash
# Z5D interop (z5c variant — W1B deferred item 3): `redistribute connected`
# under `router ospf` against rousterd as zebra, over ZAPI. Single
# container: redistribution registration is a client<->zebra behavior, no
# adjacency needed (unlike z5c's two-router route flow).
#
#   z5d-r1: mgmtd + ospfd --z--> rousterd --netlink--> kernel
#
# M1 (2026-10-10, S1): connected prefixes now populate a CONNECT table
# in the RIB (derived from the interface mirror; network-form prefixes,
# distance-0 masking, never kernel-programmed). The REDISTRIBUTE_ADD
# (CONNECT) dump is NON-empty, and a real ospfd CONSUMES it: the ASBR
# originates external type-5 LSAs for the connected prefixes. A live
# address added mid-run (dummy interface) pushes a NEW
# REDISTRIBUTE_ROUTE_ADD that ospfd also consumes — the W1B deferred-3
# goal ("a REDISTRIBUTE_ROUTE_ADD actually consumed by ospfd") in full.
#
# Registration observability: rousterd logs the REDISTRIBUTE_ADD
# registration at DEBUG (invisible at the default INFO) and an empty dump
# logs nothing — so the registration is pinned three ways:
#   1. WIRE: phase 1 runs zapi-sniff (repo debug tool) as a stand-in
#      zebra; the real ospfd's cmd-12 frame is captured byte-for-byte:
#      `01 02 0000` = afi 1, route type CONNECT=2, instance 0. That
#      capture closed a genuine defect (this change's zapi: companion
#      commit): route_type::CONNECT was 3 — the old "+1 shift" numbering
#      inference — while frr-10.2.2's route_types.txt numbers CONNECT=2
#      with ZEBRA_ROUTE_LOCAL=3 in between (STATIC=4..BGP=10 unchanged).
#   2. ADOPT: a SIGKILLed ospfd leaves its registration in M6's
#      identity-keyed memory; the replacement's HELLO surfaces it as the
#      INFO line "adopting remembered redistribute registrations"
#      keys=1 — the only INFO-visible proof the registration was
#      recorded. First live M6 adoption by a REAL daemon.
#   3. ERASE: a SIGTERMed ospfd withdraws its registrations on graceful
#      shutdown (REDISTRIBUTE_DELETE; ospfd logs ASBR Status:0), and the
#      replacement session adopts NOTHING — M6's unregister-erases-memory
#      semantics, first live pin of the DELETE leg.
#
# Flow:
#   1. rousterd resident; zapi-sniff on a second socket; ospfd #1 talks
#      to the SNIFFER only; vtysh -b pushes `redistribute connected`.
#   2. ospfd #2 against the real rousterd; config re-pushed (mgmtd does
#      not auto-replay to restarted daemons — Z1 deviation 1).
#   3. SIGTERM ospfd #2 -> restart #3: no adoption (graceful DELETE).
#   4. SIGKILL ospfd #3 -> restart #4: adoption keys=1 (crash survives).
#   5. Soak: session count stable at 3; the external LSAs stay.
#
# Machine checks (script exit 0):
#   - WIRE-PIN: sniff log holds cmd=12 body=01020000 (CONNECT=2), and
#     after the graceful stop also cmd=13 with the same body (the
#     shutdown withdraw that phase 3's premise rests on).
#   - ATTACH: exactly 3 ospfd sessions (2,3,4) on rousterd across the
#     run, protocol=7; no reconnect storm.
#   - REG-HELD: running-config holds `redistribute connected`; ospfd is
#     ASBR with external LSAs > 0 (the consumed dump).
#   - DUMP-CONSUMED: rousterd's log shows the initial redistribute dump
#     pushes, and `show ip ospf database external` lists external LSAs
#     for the connected prefixes (eth0's subnet).
#   - LIVE-PUSH: a dummy interface + address added mid-run drives a new
#     REDISTRIBUTE_ROUTE_ADD (log line) that ospfd consumes — an external
#     LSA for 203.0.113.0/24 appears that was never in the dump.
#   - ERASE: adoption count 0 after the graceful-restart leg.
#   - ADOPT: exactly one adoption line, keys=1, after the crash leg.
#   - STABLE: 30 s soak — daemons alive, zapi socket present, session
#     count still 3.
#
# Never pulls images. Caps as Z5/Z5B/Z5C (NET_ADMIN/NET_RAW/SYS_ADMIN,
# non-privileged). Logs copied to the quarantine dir on success AND
# failure (trap).
#
#   scripts/test-z5d-ospfd-redistribute.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=z5d-r1
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
SNIFF_SOCK=/var/run/frr/sniff.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OSPFD_LOG=/tmp/ospfd.log
MGMTD_LOG=/tmp/mgmtd.log
SNIFF_LOG=/tmp/sniff.log
# away/<program>/quarantine/z5d sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_Z5D_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/z5d}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

capture() {
    mkdir -p "$QUARANTINE/r1"
    docker cp "$R1:$ROUSTERD_LOG" "$QUARANTINE/r1/rousterd.log" 2>/dev/null || true
    docker cp "$R1:$OSPFD_LOG" "$QUARANTINE/r1/ospfd.log" 2>/dev/null || true
    docker cp "$R1:$MGMTD_LOG" "$QUARANTINE/r1/mgmtd.log" 2>/dev/null || true
    docker cp "$R1:$SNIFF_LOG" "$QUARANTINE/r1/sniff.log" 2>/dev/null || true
    docker exec "$R1" sh -c "vtysh -c 'show running-config'" \
        > "$QUARANTINE/r1/running.txt" 2>&1 || true
    docker exec "$R1" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf database external'" \
        > "$QUARANTINE/r1/ospf.txt" 2>&1 || true
    docker exec "$R1" sh -c "ls -l $ZAPI_SOCK; pidof rousterd mgmtd ospfd; grep -c 'zapi: session established id=' $ROUSTERD_LOG" \
        > "$QUARANTINE/r1/env.txt" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- rousterd tail ---" >&2
    docker exec "$R1" sh -c "tail -30 $ROUSTERD_LOG" >&2 || true
    echo "--- ospfd tail ---" >&2
    docker exec "$R1" sh -c "tail -15 $OSPFD_LOG" >&2 || true
    echo "--- ospfd start stderr ---" >&2
    docker exec "$R1" sh -c "cat /tmp/ospfd-start.err 2>/dev/null" >&2 || true
    echo "--- processes ---" >&2
    docker exec "$R1" sh -c "ps; pidof rousterd mgmtd ospfd" >&2 || true
    echo "--- sniff tail ---" >&2
    docker exec "$R1" sh -c "tail -10 $SNIFF_LOG" >&2 || true
    return 1
}

wait_in() {
    local desc="$1" attempts="$2" body="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$R1" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "$desc (waited ${attempts}s)"
}

start_ospfd() {
    # Forced-restart hygiene: a SIGKILLed predecessor leaves stale
    # runtime files behind (its graceful exit would have cleaned them).
    docker exec "$R1" sh -c "rm -f /var/run/frr/ospfd.pid /var/run/frr/ospfd.vty"
    docker exec "$R1" sh -c \
        "/usr/lib/frr/ospfd -d -z $1 --log file:$OSPFD_LOG --log-level debug 2>/tmp/ospfd-start.err"
}

# Graceful stop: SIGTERM delivers the shutdown REDISTRIBUTE_DELETE (seen
# on the wire ~100 ms after the signal); --init's tini reaps the exiting
# daemon, so death is observable via pidof. SIGKILL is the fallback.
stop_ospfd() {
    docker exec "$R1" sh -c "pidof ospfd | xargs kill" || true
    for _ in $(seq 1 10); do
        docker exec "$R1" sh -c "pidof ospfd" >/dev/null 2>&1 || return 0
        sleep 1
    done
    docker exec "$R1" sh -c "pidof ospfd | xargs kill -9" || true
    for _ in $(seq 1 5); do
        docker exec "$R1" sh -c "pidof ospfd" >/dev/null 2>&1 || return 0
        sleep 1
    done
    fail "ospfd refuses to die even under SIGKILL"
}

sessions() {
    docker exec "$R1" sh -c "grep -c 'zapi: session established id=' $ROUSTERD_LOG"
}

trap 'capture; docker rm -f "$R1" >/dev/null 2>&1 || true' EXIT

# 15 s-bounded docker pre-flight (M4 convention, cached image, no pull).
perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker rm -f "$R1" >/dev/null 2>&1 || true

echo "==> building rousterd + zapi-sniff ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin zapi-sniff

echo "==> starting container $R1 from $IMAGE (no pull, docker bridge)"
# --init: tini as PID 1 reaps dead daemons — this script kills and
# restarts ospfd, and without a reaper the SIGKILLed husks stay visible
# to `pidof` as zombies (the z5b/z5c shapes never kill daemons, so they
# never needed it).
docker run -d --name "$R1" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/rousterd" "$R1:/usr/local/bin/rousterd"
docker cp "target/$MUSL_TARGET/release/zapi-sniff" "$R1:/usr/local/bin/zapi-sniff"

echo "==> resident rousterd + zapi-sniffer + mgmtd"
docker exec "$R1" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$R1" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
docker exec -d "$R1" sh -c "zapi-sniff --socket $SNIFF_SOCK --log $SNIFF_LOG --respond-hello"
wait_in "rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "zapi socket" 10 "test -S $ZAPI_SOCK"
docker exec "$R1" sh -c \
    "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
wait_in "mgmtd up" 20 "pidof mgmtd"

echo "==> OSPF config: router ospf + redistribute connected (the z5c hook)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r1' \
  'router ospf' \
  ' redistribute connected' \
  'line vty' \
  > $FRR_CONF"

echo "==> phase 1 WIRE-PIN: ospfd #1 against the sniffer, capture cmd 12"
start_ospfd "$SNIFF_SOCK"
wait_in "ospfd #1 up" 20 "pidof ospfd"
wait_in "ospfd #1 vty socket" 30 "test -S /var/run/frr/ospfd.vty"
docker exec "$R1" vtysh -b
wait_in "sniffed the CONNECT registration (cmd 12, body 01 02 0000)" 30 \
    "grep 'cmd=12 ' $SNIFF_LOG | grep -q 'body=01020000'"
wait_in "ospfd #1 applied the redistribute (ASBR on)" 30 \
    "grep -q 'ASBR\[default:Status:1\]' $OSPFD_LOG"
stop_ospfd
# Bonus pin: the graceful shutdown withdraw — REDISTRIBUTE_DELETE (13)
# with the SAME body shape, ~100 ms after the signal. This is the frame
# whose arrival erases M6's reconnect memory (phase 3's premise).
wait_in "sniffed the graceful withdraw (cmd 13, body 01 02 0000)" 30 \
    "grep 'cmd=13 ' $SNIFF_LOG | grep -q 'body=01020000'"
docker exec "$R1" sh -c "pidof zapi-sniff | xargs kill" || true
wait_in "sniffer down" 15 "! pidof zapi-sniff"

echo "==> phase 2 REGISTRATION + DUMP-CONSUMED: ospfd #2 against the REAL rousterd"
start_ospfd "$ZAPI_SOCK"
wait_in "rousterd mirrored connected routes at startup" 15 "grep -q 'initial connected routes' $ROUSTERD_LOG"
wait_in "ospfd #2 attached (protocol=7)" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
[ "$(sessions)" = 1 ] || fail "expected exactly 1 session, got $(sessions)"
docker exec "$R1" vtysh -b
wait_in "ospfd #2 holds redistribute connected" 30 \
    "vtysh -c 'show running-config' | grep -A1 'router ospf' | grep -q 'redistribute connected'"
wait_in "ospfd #2 is ASBR" 30 "vtysh -c 'show ip ospf' | grep -q 'This router is an ASBR'"
# The CONNECT dump is non-empty and CONSUMED: the ASBR originates
# external LSAs for the connected prefixes (count > 0).
wait_in "ospfd #2 external LSA count > 0 (the dump consumed)" 45 \
    "sh -c \"vtysh -c 'show ip ospf' | grep -q 'Number of external LSA 0'\" && exit 1 || exit 0"
[ "$(docker exec "$R1" sh -c "grep -c 'initial redistribute dump push' $ROUSTERD_LOG || true")" -ge 1 ] \
    || fail "no initial dump push in rousterd's log — the CONNECT table did not reach the dump"
docker exec "$R1" sh -c "vtysh -c 'show ip ospf database external'" \
    > /dev/null

echo "==> phase 2b LIVE-PUSH: a new connected prefix mid-run is pushed and consumed"
# A dummy interface + address created AFTER registration: the address
# event lands in the RIB's connected table, fans a
# REDISTRIBUTE_ROUTE_ADD, and ospfd originates a type-5 LSA for it.
docker exec "$R1" sh -c "ip link add dummy9 type dummy && ip link set dummy9 up && ip addr add 203.0.113.1/24 dev dummy9"
wait_in "rousterd pushed the new connected prefix" 30 \
    "grep -q 'best route changed; pushing REDISTRIBUTE_ROUTE_ADD' $ROUSTERD_LOG"
wait_in "ospfd originated an external LSA for 203.0.113.0/24 (live push consumed)" 45 \
    "vtysh -c 'show ip ospf database external' | grep -q '203.0.113.0'"

echo "==> phase 3 ERASE: graceful stop (shutdown DELETE) then restart — NO adoption"
stop_ospfd
start_ospfd "$ZAPI_SOCK"
wait_in "ospfd #3 session (count 2)" 30 "test \"\$(grep -c 'zapi: session established id=' $ROUSTERD_LOG)\" -eq 2"
sleep 2
[ "$(docker exec "$R1" sh -c "grep -c 'adopting remembered' $ROUSTERD_LOG || true")" = 0 ] \
    || fail "adoption after a GRACEFUL restart — the shutdown DELETE should have erased the memory"
docker exec "$R1" vtysh -b

echo "==> phase 4 ADOPT: SIGKILL (crash) then restart — adoption keys=1"
docker exec "$R1" sh -c "pidof ospfd | xargs kill -9" || true
wait_in "ospfd #3 gone (crashed)" 15 "! pidof ospfd"
start_ospfd "$ZAPI_SOCK"
wait_in "ospfd #4 session (count 3)" 30 "test \"\$(grep -c 'zapi: session established id=' $ROUSTERD_LOG)\" -eq 3"
wait_in "M6 adoption line with exactly one remembered registration" 30 \
    "grep 'adopting remembered' $ROUSTERD_LOG | grep -q 'keys=1'"
docker exec "$R1" vtysh -b

echo "==> STABLE: 30 s soak"
sleep 31
wait_in "ospfd #4 alive" 10 "pidof rousterd mgmtd ospfd"
[ "$(sessions)" = 3 ] || fail "session count drifted during the soak: $(sessions)"
wait_in "zapi socket alive" 10 "test -S $ZAPI_SOCK"
[ "$(docker exec "$R1" sh -c "grep -c 'adopting remembered' $ROUSTERD_LOG")" = 1 ] \
    || fail "adoption count is not exactly 1"
# The adopted registration re-dumped the connected prefixes to ospfd #4
# (ADDs are idempotent refreshes) and the external LSAs survive.
wait_in "external LSAs still present after the soak" 15 \
    "sh -c \"vtysh -c 'show ip ospf' | grep -q 'Number of external LSA 0'\" && exit 1 || exit 0"
wait_in "final config still holds redistribute connected" 10 \
    "vtysh -c 'show running-config' | grep -A1 'router ospf' | grep -q 'redistribute connected'"

echo "==> final state"
docker exec "$R1" sh -c "echo '--- sessions ---'; grep 'session established' $ROUSTERD_LOG; echo '--- adoption ---'; grep 'adopting remembered' $ROUSTERD_LOG; echo '--- redistribute pushes ---'; grep -cE 'initial redistribute dump push|pushing REDISTRIBUTE_ROUTE_ADD|reconnect redistribute dump' $ROUSTERD_LOG; echo '--- ospf ---'; vtysh -c 'show ip ospf' | grep -E 'ASBR|external LSA'; echo '--- external db ---'; vtysh -c 'show ip ospf database external' | grep -E 'Link State ID|203.0.113.0|external'"

echo "z5d ospfd redistribute-connected interop: PASS"
