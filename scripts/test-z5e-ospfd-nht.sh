#!/usr/bin/env bash
# Z5E interop (z5d variant — W1B deferred item 4, A23): ospfd NHT
# coverage. `area <id> nssa default-information-originate` makes a real
# FRR 10.2.2 ospfd send NEXTHOP_REGISTER (21) for 0.0.0.0/0 — the NSSA
# default import check (ospf_area_nssa_default_originate_set ->
# ospf_zebra_import_default_route, ospfd.c; only NHT sender in ospfd).
# Single container, same shape as z5d: no adjacency needed.
#
#   z5e-r1: mgmtd + ospfd --z--> rousterd --netlink--> kernel
#
# The registration is the FIRST live client sample with
# resolve_via_default=1 (staticd/bgpd fixtures send 0), and the only /0
# registration. Zebra answers such an RNH from the routing table, gated
# on exactly that flag (zebra_rnh.c zebra_rnh_resolve_nexthop_entry:
# the default prefix may resolve an RNH only when
# ZEBRA_NHT_RESOLVE_VIA_DEFAULT is set); rousterd's answer grew the
# same shape this change: on-link first (unchanged for flag-0 clients),
# then a longest-prefix match over the observed kernel mirror (which
# now records each kernel route's RTA_GATEWAY/RTA_OIF).
#
# Flow:
#   1. WIRE-PIN: ospfd #1 against zapi-sniff; the cmd-21 frame is
#      captured byte-for-byte (body 0001000100020000000000 =
#      connected=0, resolve_via_default=1, safi=1, 0.0.0.0/0). Graceful
#      SIGTERM withdraws REDISTRIBUTE_DELETE (13) but NEVER
#      NEXTHOP_UNREGISTER (22) — pinned on the wire.
#   2. ANSWER: ospfd #2 against the REAL rousterd (default route
#      present). rousterd logs the registration at INFO; the resolved
#      NEXTHOP_UPDATE drives ospfd to originate the NSSA type-7 default
#      LSA (0.0.0.0/0) — `ospf_zebra_import_check_update` sets
#      nssa_default_import_check.status from the update's nexthop count,
#      and ospf_abr_nssa_type7_defaults originates on true. The LSA is
#      the machine-checkable proof ospfd CONSUMED the answer.
#   3. DIFFERENTIAL: `ip route del default` empties the kernel mirror;
#      ospfd #3 re-registers and gets the truthful unresolved answer —
#      NO type-7 default. Restoring the default and restarting (#4)
#      brings the LSA back. (Fresh registrations only: route events are
#      not resolution flips — the pinned Z3B boundary.)
#   4. STABLE: 30 s soak — daemons alive, session count steady, LSA in
#      place.
#
# Machine checks (script exit 0): see the wait_in/assert lines below.
#
# Never pulls images. Caps as Z5/Z5B/Z5C/Z5D (NET_ADMIN/NET_RAW/
# SYS_ADMIN, non-privileged, --init for the ospfd restarts). Logs are
# copied to the quarantine dir on success AND failure (trap).
#
#   scripts/test-z5e-ospfd-nht.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=z5e-r1
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
SNIFF_SOCK=/var/run/frr/sniff.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OSPFD_LOG=/tmp/ospfd.log
MGMTD_LOG=/tmp/mgmtd.log
SNIFF_LOG=/tmp/sniff.log
# away/<program>/quarantine/z5e sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_Z5E_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/z5e}"
# The registration body pinned in phase 1 (zapi-sniff hex, no spaces).
NHT_BODY=0001000100020000000000

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
    docker exec "$R1" sh -c "vtysh -c 'show running-config'; echo ---; vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf database'" \
        > "$QUARANTINE/r1/ospf.txt" 2>&1 || true
    docker exec "$R1" sh -c "ip route show; echo ---; ls -l $ZAPI_SOCK; pidof rousterd mgmtd ospfd; grep -c 'zapi: session established id=' $ROUSTERD_LOG" \
        > "$QUARANTINE/r1/env.txt" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- rousterd tail ---" >&2
    docker exec "$R1" sh -c "tail -30 $ROUSTERD_LOG" >&2 || true
    echo "--- ospfd tail ---" >&2
    docker exec "$R1" sh -c "tail -15 $OSPFD_LOG" >&2 || true
    echo "--- ospf database ---" >&2
    docker exec "$R1" sh -c "vtysh -c 'show ip ospf database'" >&2 || true
    echo "--- routes ---" >&2
    docker exec "$R1" sh -c "ip route show" >&2 || true
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
    docker exec "$R1" sh -c "rm -f /var/run/frr/ospfd.pid /var/run/frr/ospfd.vty"
    docker exec "$R1" sh -c \
        "/usr/lib/frr/ospfd -d -z $1 --log file:$OSPFD_LOG --log-level debug 2>/dev/null"
}

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
docker run -d --name "$R1" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/rousterd" "$R1:/usr/local/bin/rousterd"
docker cp "target/$MUSL_TARGET/release/zapi-sniff" "$R1:/usr/local/bin/zapi-sniff"

echo "==> resident rousterd + zapi-sniffer + mgmtd"
docker exec "$R1" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$R1" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
docker exec -d "$R1" sh -c "zapi-sniff --socket $SNIFF_SOCK --log $SNIFF_LOG --respond-hello"
wait_in "rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "zapi socket" 10 "test -S $ZAPI_SOCK"
docker exec "$R1" sh -c \
    "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
wait_in "mgmtd up" 20 "pidof mgmtd"

GW=$(docker exec "$R1" sh -c "ip route show default" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)
[ -n "$GW" ] || fail "no default route to test against"
echo "==> kernel default gateway: $GW"

# M3 (neighbour-liveness gate on the NEXTHOP_UPDATE answer): the /0
# answer resolves through the default's gateway, and a gateway is only
# ACTIVE with a confirmed neighbour entry. A quiet container never ARPs
# the bridge gateway, so make the deployment-with-traffic shape
# explicitly: one ping teaches eth0 the gateway's lladdr (REACHABLE,
# later STALE — both confirmed for the gate). Without this the answer
# is truthful-but-unresolved and ospfd correctly never originates the
# type-7 default.
docker exec "$R1" ping -c1 -W1 "$GW" >/dev/null 2>&1 || true
docker exec "$R1" sh -c "ip neigh show $GW dev eth0" | grep -q lladdr \
    || fail "gateway $GW has no lladdr neighbour after warm-up ping"

echo "==> OSPF config: redistribute connected (ASBR) + NSSA default-originate (the NHT trigger)"

echo "==> OSPF config: redistribute connected (ASBR) + NSSA default-originate (the NHT trigger)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r1' \
  'router ospf' \
  ' redistribute connected' \
  ' area 0.0.0.1 nssa default-information-originate' \
  'line vty' \
  > $FRR_CONF"

echo "==> phase 1 WIRE-PIN: ospfd #1 against the sniffer, capture cmd 21"
start_ospfd "$SNIFF_SOCK"
wait_in "ospfd #1 up" 20 "pidof ospfd"
wait_in "ospfd #1 vty socket" 30 "test -S /var/run/frr/ospfd.vty"
docker exec "$R1" vtysh -b
wait_in "sniffed the ospfd NHT registration (cmd 21)" 30 \
    "grep 'cmd=21 ' $SNIFF_LOG | grep -q 'body=$NHT_BODY'"
if docker exec "$R1" sh -c "grep -q 'cmd=22 ' $SNIFF_LOG"; then
    fail "unexpected NEXTHOP_UNREGISTER seen on the wire"
fi
# Graceful shutdown: the redistribute withdraw appears, the NHT
# unregistration does NOT (lib/zclient.c never sends it on close).
stop_ospfd
wait_in "sniffed the graceful redistribute withdraw (cmd 13)" 30 \
    "grep 'cmd=13 ' $SNIFF_LOG | grep -q 'body=01020000'"
if docker exec "$R1" sh -c "grep -q 'cmd=22 ' $SNIFF_LOG"; then
    fail "SIGTERM must not produce NEXTHOP_UNREGISTER (no unregister on shutdown)"
fi
docker exec "$R1" sh -c "pidof zapi-sniff | xargs kill" || true
wait_in "sniffer down" 15 "! pidof zapi-sniff"

echo "==> phase 2 ANSWER: ospfd #2 against the REAL rousterd (default present)"
start_ospfd "$ZAPI_SOCK"
wait_in "ospfd #2 attached (protocol=7)" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
[ "$(sessions)" = 1 ] || fail "expected exactly 1 session, got $(sessions)"
docker exec "$R1" vtysh -b
wait_in "rousterd logged the ospfd registration (flag set)" 30 \
    "grep 'zapi: nexthop register' $ROUSTERD_LOG | grep -q 'prefix=0.0.0.0/0.*resolve_via_default=true'"
wait_in "ospfd #2 originated the NSSA type-7 default (answer consumed)" 45 \
    "vtysh -c 'show ip ospf database' | grep 'NSSA-external' -A3 | grep -q '0.0.0.0'"
[ "$(sessions)" = 1 ] || fail "session count drifted after the answer: $(sessions)"

echo "==> phase 3 DIFFERENTIAL: no default -> unresolved -> no type-7"
stop_ospfd
docker exec "$R1" sh -c "ip route del default"
start_ospfd "$ZAPI_SOCK"
wait_in "ospfd #3 attached" 30 "test \"\$(grep -c 'zapi: session established id=' $ROUSTERD_LOG)\" -eq 2"
docker exec "$R1" vtysh -b
wait_in "ospfd #3 re-registered" 30 \
    "test \"\$(grep -c 'zapi: nexthop register' $ROUSTERD_LOG)\" -ge 2"
sleep 4
if docker exec "$R1" sh -c "vtysh -c 'show ip ospf database' | grep -q 'NSSA-external'"; then
    fail "type-7 default originated WITHOUT a default route — the unresolved answer was not honored"
fi

echo "==> phase 3b restore: default back -> resolved -> type-7 returns"
stop_ospfd
docker exec "$R1" sh -c "ip route add default via $GW dev eth0"
start_ospfd "$ZAPI_SOCK"
wait_in "ospfd #4 attached" 30 "test \"\$(grep -c 'zapi: session established id=' $ROUSTERD_LOG)\" -eq 3"
docker exec "$R1" vtysh -b
wait_in "ospfd #4 originated the type-7 default again" 45 \
    "vtysh -c 'show ip ospf database' | grep 'NSSA-external' -A3 | grep -q '0.0.0.0'"

echo "==> STABLE: 30 s soak"
sleep 31
wait_in "ospfd #4 alive" 10 "pidof rousterd mgmtd ospfd"
[ "$(sessions)" = 3 ] || fail "session count drifted during the soak: $(sessions)"
wait_in "zapi socket alive" 10 "test -S $ZAPI_SOCK"
wait_in "type-7 default still in place" 10 \
    "vtysh -c 'show ip ospf database' | grep 'NSSA-external' -A3 | grep -q '0.0.0.0'"
wait_in "kernel default restored" 10 "ip route show default | grep -q via"

echo "==> final state"
docker exec "$R1" sh -c "echo '--- registrations ---'; grep 'nexthop register' $ROUSTERD_LOG; echo '--- database ---'; vtysh -c 'show ip ospf database' | grep -A3 'NSSA-external'"

echo "z5e ospfd NHT interop: PASS"
