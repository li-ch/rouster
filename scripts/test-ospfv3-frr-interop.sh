#!/usr/bin/env bash
# OSPFv3-FRR interop (S7-a, the AF-generic proof, live): Rouster's
# ospfd — `address-family ipv6-unicast`, the daemon_v3 core over the
# v6 raw transport — forms a FULL OSPFv3 adjacency with the REAL FRR
# 10.2.2 ospf6d over a shared v6 network (the docker bridge as a p2p
# link), both zebras = rousterd.
#
#   ospf6d-frr-r1 (FRR):  rousterd + mgmtd + staticd + REAL ospf6d
#   ospf6d-rouster-r2:    rousterd + mgmtd + staticd + rouster ospfd(v3)
#
#   area 0.0.0.0 over eth0's LINK-LOCAL addresses only (the RFC 5340
#   §2.5 model: OSPFv3 packets source the interface's link-local;
#   hellos multicast to ff02::5), hellos 2 s / dead 8 s, router IDs
#   pinned (FRR 10.255.1.1, ours 10.255.2.1), instance ID 0 both
#   sides, `ipv6 ospf6 network point-to-point` on FRR's side.
#
# Machine checks (script exit 0):
#   - ATTACH: both daemons' zapi sessions established as protocol=8
#     (OSPF6) with rousterd; neither reconnects.
#   - ADJACENCY-BOTH: FRR `show ipv6 ospf6 neighbor` reports Full AND
#     our ospfd logged "ospfv3: adjacency FULL".
#   - LSDB-BOTH: FRR's `show ipv6 ospf6 database` carries OUR
#     router-LSA + link-LSA (adv 10.255.2.1); our ospfd logged the
#     peer router-LSA install (both flooding scopes converge — the
#     link-LSA lives in the per-interface link store).
#   - REDIST-OUT: staticd on r2 injects 2001:db8:99::/64 (blackhole)
#     -> rousterd pushes the v6 STATIC redistribute to our registered
#     ospfd -> WE originate the 0x4005 AS-external LSA -> FRR
#     computes it (via our link-local, its link-LSA next-hop lookup)
#     -> r1's kernel `proto ospf` route through rousterd.
#   - REDIST-IN: staticd on r1 + FRR `redistribute static` -> FRR's
#     type-5 -> our §16.4-lite direct-ASBR calc -> "ospfv3: route
#     installed" -> ROUTE_ADD through rousterd -> r2 kernel
#     `proto ospf` via FRR's link-local.
#   - SOAK: 30 s — still Full, routes still present, no zapi
#     reconnects, every daemon alive.
#
# Never pulls images (frr-testbed:10.2.2 cached); self-cleaning;
# quarantine (absolute path) under away/2026-10-14/quarantine/n3v6 on
# success AND failure (env-overridable). NOTE the rig deviation from
# the v2 family: containers run --privileged — IPv6 arrives disabled
# on fresh docker-desktop netns interfaces (disable_ipv6=1) and the
# sysctl write needs /proc/sys writable; the caps-only family shape
# cannot bring v6 up here.
#
#   scripts/test-ospfv3-frr-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf6d-frr-r1
R2=ospf6d-rouster-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OUR_OSPFD_LOG=/var/log/rouster-ospfd.log
FRR_OSPF6D_LOG=/tmp/ospf6d.log
STATICD_LOG=/tmp/staticd.log
MGMTD_LOG=/tmp/mgmtd.log
# Router IDs: FRR = 10.255.1.1, ours = 10.255.2.1.
FRR_RID=10.255.1.1
OUR_RID=10.255.2.1
OUR_STATIC=2001:db8:99::/64   # ours -> redistribute -> FRR's kernel
FRR_STATIC=2001:db8:88::/64   # FRR's -> redistribute -> our kernel
QUARANTINE="${ROUSTER_OSPFV3_QUARANTINE:-$(cd "$(dirname "$0")/.." && pwd)/away/2026-10-14/quarantine/n3v6}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# eth0's auto-generated link-local (fe80::/64, scope link).
link_local() {
    docker exec "$1" sh -c "ip -6 addr show dev eth0 scope link" \
        | sed -n 's/.*inet6 \(fe80::[0-9a-f:]*\)\/64 .*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="$R1"; [ "$side" = r2 ] && name="$R2"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip -6 route show; echo ---; ip -6 route show proto ospf" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ipv6 ospf6'; echo ---; vtysh -c 'show ipv6 ospf6 neighbor'; echo ---; vtysh -c 'show ipv6 ospf6 database'; echo ---; vtysh -c 'show ipv6 route'" \
            > "$QUARANTINE/$side/ospf6.txt" 2>&1 || true
        docker exec "$name" sh -c "ip -6 addr show dev eth0" \
            > "$QUARANTINE/$side/addr.txt" 2>&1 || true
        docker cp "$name:$STATICD_LOG" "$QUARANTINE/$side/staticd.log" 2>/dev/null || true
        docker cp "$name:$MGMTD_LOG" "$QUARANTINE/$side/mgmtd.log" 2>/dev/null || true
    done
    docker cp "$R1:$FRR_OSPF6D_LOG" "$QUARANTINE/r1/frr-ospf6d.log" 2>/dev/null || true
    docker cp "$R1:$FRR_CONF" "$QUARANTINE/r1/frr.conf" 2>/dev/null || true
    docker cp "$R2:$OUR_OSPFD_LOG" "$QUARANTINE/r2/rouster-ospfd.log" 2>/dev/null || true
    docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf" \
        > "$QUARANTINE/r2/rouster-ospfd.conf" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    for entry in "$R1:$ROUSTERD_LOG rousterd-r1" "$R2:$ROUSTERD_LOG rousterd-r2"; do
        name="${entry%%:*}"; what="${entry#*:}"; log="${what%% *}"
        echo "--- $what tail ---" >&2
        docker exec "$name" sh -c "tail -25 $log" >&2 || true
    done
    echo "--- our ospfd tail ---" >&2
    docker exec "$R2" sh -c "tail -40 $OUR_OSPFD_LOG" >&2 || true
    echo "--- FRR ospf6d tail ---" >&2
    docker exec "$R1" sh -c "tail -30 $FRR_OSPF6D_LOG" >&2 || true
    echo "--- FRR ospf6 neighbor ---" >&2
    docker exec "$R1" sh -c "vtysh -c 'show ipv6 ospf6 neighbor'" >&2 || true
    return 1
}

wait_in() {
    local container="$1" desc="$2" attempts="$3" body="$4"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$container" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "$desc (waited ${attempts}s, $container)"
}

# 15 s docker pre-flight probe (the run-smokes convention).
perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }

trap 'capture; docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true

echo "==> building rousterd + ospfd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin ospfd

echo "==> starting containers from $IMAGE (--privileged: the v6 sysctl write)"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --privileged \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/ospfd" "$name:/usr/local/bin/rouster-ospfd"
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
    # IPv6 up on eth0 (docker-desktop ships netns interfaces with
    # disable_ipv6=1 — the reason this rig runs privileged).
    docker exec "$name" sh -c \
        "echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6; \
         echo 0 > /proc/sys/net/ipv6/conf/default.disable_ipv6; \
         ip link set eth0 up; echo 0 > /proc/sys/net/ipv6/conf/eth0/disable_ipv6 || true"
done

# Wait for the kernel's auto link-local on eth0 (the §2.5 source).
for name in "$R1" "$R2"; do
    wait_in "$name" "eth0 link-local" 15 "ip -6 addr show dev eth0 scope link | grep -q fe80"
done
R1_LL=$(link_local "$R1")
R2_LL=$(link_local "$R2")
[ -n "$R1_LL" ] && [ -n "$R2_LL" ] || fail "no link-local addresses"
echo "==> link-locals: r1=$R1_LL r2=$R2_LL"

echo "==> resident rousterd (zebra) in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d -e ROUSTERD_LOG=debug "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in "$R1" "r1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$R2" "r2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> r1: mgmtd + staticd + REAL FRR ospf6d against rousterd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/ospf6d -d -z $ZAPI_SOCK --log file:$FRR_OSPF6D_LOG --log-level debug"
wait_in "$R1" "r1 FRR daemons up" 30 "pidof mgmtd staticd ospf6d"
wait_in "$R1" "r1 ospf6d vty socket" 30 "test -S /var/run/frr/ospf6d.vty"

echo "==> r2: mgmtd + staticd (FRR) + OUR ospfd (v3) against rousterd"
docker exec "$R2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R2" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router ospf' \
  ' address-family ipv6-unicast' \
  ' router-id $OUR_RID' \
  ' area 0.0.0.0' \
  '  interface eth0' \
  '   link-local $R2_LL' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' redistribute static' \
  > /etc/rouster-ospfd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 ROUSTER_OSPFV3_TRACE=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R2" "our ospfd(v3) is up" 10 "pidof rouster-ospfd"
wait_in "$R2" "our v3 core constructed" 10 "grep -q 'ospfv3: running' $OUR_OSPFD_LOG"

echo "==> FRR ospf6d config (vtysh -b, retried past the zebra-view race)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf6d-frr-r1' \
  'interface eth0' \
  ' ipv6 ospf6 area 0.0.0.0' \
  ' ipv6 ospf6 network point-to-point' \
  ' ipv6 ospf6 hello-interval 2' \
  ' ipv6 ospf6 dead-interval 8' \
  'router ospf6' \
  ' ospf6 router-id $FRR_RID' \
  ' redistribute static' \
  'line vty' \
  > $FRR_CONF"
# Exactly TWO applies ever, spaced: each vtysh -b re-read resets the
# ospf6d adjacencies (probed live: the neighbor flaps per re-apply),
# so the v2 script's retry-until-visible loop cannot be used here.
APPLIED=0
for attempt in 1 2; do
    docker exec "$R1" vtysh -b >/dev/null 2>&1 || true
    for _ in $(seq 1 10); do
        if docker exec "$R1" sh -c "vtysh -c 'show running-config' 2>/dev/null | grep -q 'ipv6 ospf6 network point-to-point'"; then
            APPLIED=1
            break
        fi
        sleep 1
    done
    [ "$APPLIED" = 1 ] && break
    sleep 2
done
[ "$APPLIED" = 1 ] || fail "FRR ospf6d config never applied (zebra-view race)"

echo "==> ATTACH: both zapi sessions established (protocol=8, OSPF6)"
wait_in "$R1" "r1 (FRR ospf6d) attached" 30 "grep -q 'session established.*protocol=8' $ROUSTERD_LOG"
wait_in "$R2" "r2 (our v3 ospfd) attached" 30 "grep -q 'session established.*protocol=8' $ROUSTERD_LOG"
R1_SESSIONS=$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")
R2_SESSIONS=$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")

echo "==> ADJACENCY-BOTH: waiting for Full on both sides"
wait_in "$R1" "FRR neighbor Full" 90 "vtysh -c 'show ipv6 ospf6 neighbor' | grep -q Full"
wait_in "$R2" "our ospfd logged adjacency FULL" 90 "grep -q 'ospfv3: adjacency FULL' $OUR_OSPFD_LOG"

echo "==> LSDB-BOTH: each database holds the other's router- and link-LSA"
wait_in "$R1" "FRR's database holds our LSAs" 30 \
    "vtysh -c 'show ipv6 ospf6 database' | grep -q '$OUR_RID'"
wait_in "$R2" "our databases hold FRR's router-LSA" 30 \
    "grep 'ospfv3: peer LSA installed' $OUR_OSPFD_LOG | grep -q 'lsa=.router'"
wait_in "$R2" "our LINK-scope store holds FRR's link-LSA" 30 \
    "grep 'ospfv3: peer LSA installed' $OUR_OSPFD_LOG | grep -q 'lsa=.link'"

echo "==> REDIST-OUT: staticd injects $OUR_STATIC -> our type-5 -> FRR's kernel"
docker exec "$R2" vtysh -c "configure terminal" -c "ipv6 route $OUR_STATIC blackhole"
wait_in "$R2" "our ospfd originated the external LSA" 20 \
    "grep 'external LSA originated' $OUR_OSPFD_LOG | grep -q '${OUR_STATIC%/*}'"
wait_in "$R1" "FRR holds our external LSA" 30 \
    "vtysh -c 'show ipv6 ospf6 database' | grep '$OUR_RID' | grep -q '${OUR_STATIC%/*}'"
# FRR's RIB is rousterd-backed: the proof is the kernel route.
wait_in "$R1" "$OUR_STATIC in r1 kernel via OSPF" 30 \
    "ip -6 route show proto ospf | grep -q '$OUR_STATIC'"

echo "==> REDIST-IN: FRR's static -> FRR type-5 -> our direct-ASBR calc -> r2 kernel"
docker exec "$R1" vtysh -c "configure terminal" -c "ipv6 route $FRR_STATIC blackhole"
wait_in "$R1" "FRR originated its external LSA" 30 \
    "vtysh -c 'show ipv6 ospf6 database' | grep '$FRR_RID' | grep -q '${FRR_STATIC%/*}'"
wait_in "$R2" "our ospfd installed FRR's external route" 30 \
    "grep 'ospfv3: route installed' $OUR_OSPFD_LOG | grep -q '${FRR_STATIC%/*}'"
wait_in "$R2" "r2 rousterd exported it to the kernel" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '${FRR_STATIC%/*}'"
wait_in "$R2" "$FRR_STATIC in r2 kernel proto ospf via FRR" 30 \
    "ip -6 route show proto ospf | grep '$FRR_STATIC' | grep -q via"

echo "==> SOAK: 30 s adjacency/route stability"
sleep 30
docker exec "$R1" sh -c "vtysh -c 'show ipv6 ospf6 neighbor' | grep -q Full" \
    || fail "FRR adjacency dropped during soak"
docker exec "$R2" sh -c "grep -q 'ospfv3: adjacency FULL' $OUR_OSPFD_LOG" \
    || fail "our adjacency dropped during soak"
docker exec "$R2" sh -c "ip -6 route show proto ospf | grep -q '$FRR_STATIC'" \
    || fail "external route lost during soak"
docker exec "$R1" sh -c "ip -6 route show proto ospf | grep -q '$OUR_STATIC'" \
    || fail "our external route lost from r1 during soak"
[ "$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")" = "$R1_SESSIONS" ] \
    || fail "r1 saw a zapi reconnect during the soak"
[ "$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")" = "$R2_SESSIONS" ] \
    || fail "r2 saw a zapi reconnect during the soak"
docker exec "$R1" sh -c "pidof rousterd mgmtd staticd ospf6d" >/dev/null \
    || fail "an r1 daemon died during the soak"
docker exec "$R2" sh -c "pidof rousterd mgmtd staticd rouster-ospfd" >/dev/null \
    || fail "an r2 daemon died during the soak"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show ipv6 ospf6 neighbor'; echo ---; ip -6 route show proto ospf"
docker exec "$R2" sh -c "ip -6 route show proto ospf"

echo "ospfv3-frr interop: PASS"
