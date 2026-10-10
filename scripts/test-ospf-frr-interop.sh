#!/usr/bin/env bash
# OSPF-FRR interop (W2-e, M6): Rouster's ospfd forms a FULL OSPFv2
# adjacency with the REAL FRR 10.2.2 ospfd over a p2p link (the
# docker bridge with `ip ospf network point-to-point` both sides —
# no DR election, §C.3's p2p arm), both zebras = rousterd.
#
#   ospf-frr-r1 (FRR):  rousterd + mgmtd + staticd + REAL ospfd
#   ospf-rouster-r2:    rousterd + mgmtd + staticd + rouster ospfd
#
#   area 0.0.0.0, hellos 2 s / dead 8 s, router IDs pinned
#   (FRR 10.255.1.1, ours 10.255.2.1 — the larger ID masters the DD
#   exchange, §10.6).
#
# Machine checks (script exit 0):
#   - ATTACH: r2's rousterd logged a protocol=7 (OSPF) session for
#     OUR ospfd; r1's for the real ospfd; neither reconnects.
#   - ADJACENCY-BOTH: FRR `show ip ospf neighbor` reports Full AND
#     our ospfd logged "adjacency FULL".
#   - LSDB-BOTH: FRR's `show ip ospf database router` carries OUR
#     router-LSA (adv 10.255.2.1); our ospfd logged OSPF route
#     installs derived from FRR's router-LSA (the stub network).
#   - REDIST-OUT (the milestone's injected route): staticd on r2
#     injects 198.51.100.0/24 -> rousterd pushes the STATIC
#     redistribute to our registered ospfd -> WE originate the
#     type-5 LSA -> FRR installs it (show ip route: O E2; database
#     external adv 10.255.2.1).
#   - REDIST-IN (vice versa): staticd on r1 + FRR `redistribute
#     static` -> FRR's type-5 (203.0.113.0/24) -> our §16.4 external
#     calculation -> route installed log + ROUTE_ADD through
#     rousterd -> r2 kernel `proto ospf`.
#   - KERNEL-EXPORT: our SPF route adds reached rousterd (the
#     transit stub itself is connected-covered in the kernel — the
#     external routes below carry the kernel-visible proof).
#   - SOAK: 30 s — both still Full, routes still present, no zapi
#     reconnects, every daemon alive.
#
# Never pulls images (frr-testbed:10.2.2 cached); caps as the z5/bgp
# family (NET_ADMIN/NET_RAW/SYS_ADMIN — raw proto-89 sockets need
# NET_RAW); self-cleaning; quarantine (absolute path) under
# away/2026-10-11/weekend/quarantine/ospf/ on success AND failure.
#
#   scripts/test-ospf-frr-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf-frr-r1
R2=ospf-rouster-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OUR_OSPFD_LOG=/var/log/rouster-ospfd.log
FRR_OSPFD_LOG=/tmp/ospfd.log
STATICD_LOG=/tmp/staticd.log
MGMTD_LOG=/tmp/mgmtd.log
# Router IDs: FRR = 10.255.1.1, ours = 10.255.2.1 (larger → master).
FRR_RID=10.255.1.1
OUR_RID=10.255.2.1
OUR_STATIC=198.51.100.0/24   # ours -> redistribute -> FRR's RIB
FRR_STATIC=203.0.113.0/24    # FRR's -> redistribute -> our RIB/kernel
QUARANTINE="${ROUSTER_OSPF_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/weekend/quarantine/ospf}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/\([0-9]*\) .*/\1 \2/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="$R1"; [ "$side" = r2 ] && name="$R2"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto ospf" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database'; echo ---; vtysh -c 'show ip route'" \
            > "$QUARANTINE/$side/ospf.txt" 2>&1 || true
        docker cp "$name:$STATICD_LOG" "$QUARANTINE/$side/staticd.log" 2>/dev/null || true
        docker cp "$name:$MGMTD_LOG" "$QUARANTINE/$side/mgmtd.log" 2>/dev/null || true
    done
    docker cp "$R1:$FRR_OSPFD_LOG" "$QUARANTINE/r1/frr-ospfd.log" 2>/dev/null || true
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
    docker exec "$R2" sh -c "tail -30 $OUR_OSPFD_LOG" >&2 || true
    echo "--- FRR ospfd tail ---" >&2
    docker exec "$R1" sh -c "tail -20 $FRR_OSPFD_LOG" >&2 || true
    echo "--- FRR ospf neighbor ---" >&2
    docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor'" >&2 || true
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

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/ospfd" "$name:/usr/local/bin/rouster-ospfd"
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
done

read -r R1_IP R1_LEN <<< "$(bridge_ip "$R1")"
read -r R2_IP R2_LEN <<< "$(bridge_ip "$R2")"
[ -n "$R1_IP" ] && [ -n "$R2_IP" ] || fail "no bridge addresses"
SUBNET=$(docker exec "$R1" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
echo "==> bridge: frr-r1=$R1_IP/$R1_LEN rouster-r2=$R2_IP/$R2_LEN subnet=$SUBNET"

echo "==> resident rousterd (zebra) in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in "$R1" "r1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$R2" "r2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG" 

echo "==> r1: mgmtd + staticd + REAL FRR ospfd against rousterd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
wait_in "$R1" "r1 FRR daemons up" 30 "pidof mgmtd staticd ospfd"
wait_in "$R1" "r1 ospfd vty socket" 30 "test -S /var/run/frr/ospfd.vty"

echo "==> r2: mgmtd + staticd (FRR) + OUR ospfd against rousterd"
docker exec "$R2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R2" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router ospf' \
  ' router-id $OUR_RID' \
  ' area 0.0.0.0' \
  '  interface eth0' \
  '   address $R2_IP/$R2_LEN' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' redistribute static' \
  > /etc/rouster-ospfd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R2" "our ospfd is up" 10 "pidof rouster-ospfd"

echo "==> FRR side config (vtysh -b, retried past the zebra-view race)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-frr-r1' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $FRR_RID' \
  ' network $SUBNET area 0.0.0.0' \
  ' redistribute static' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$R1" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$R1" sh -c "vtysh -c 'show ip ospf interface eth0' 2>/dev/null | grep -qi 'point-to-point'"; then
        APPLIED=1
        break
    fi
done
[ "$APPLIED" = 1 ] || fail "FRR ospf config never applied (zebra-view race)"

echo "==> ATTACH: both ospfd sessions established (protocol=7)"
wait_in "$R1" "r1 (FRR ospfd) attached" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
wait_in "$R2" "r2 (our ospfd) attached" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
R1_SESSIONS=$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")
R2_SESSIONS=$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")

echo "==> ADJACENCY-BOTH: waiting for Full on both sides"
wait_in "$R1" "FRR neighbor Full" 90 "vtysh -c 'show ip ospf neighbor' | grep -q Full"
wait_in "$R2" "our ospfd logged adjacency FULL" 90 "grep -q 'adjacency FULL' $OUR_OSPFD_LOG"

echo "==> LSDB-BOTH: each LSDB holds the other's router-LSA"
wait_in "$R1" "FRR's database holds our router-LSA" 30 \
    "vtysh -c 'show ip ospf database router' | grep -q '$OUR_RID'"
wait_in "$R2" "our ospfd installed FRR-derived routes" 30 \
    "grep -q 'OSPF route installed' $OUR_OSPFD_LOG"

echo "==> KERNEL-EXPORT: our SPF routes reached rousterd"
wait_in "$R2" "r2 rousterd logged the OSPF route add" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q 'protocol=Ospf'"

echo "==> REDIST-OUT: staticd injects $OUR_STATIC -> our type-5 -> FRR's RIB"
# Our LSA carries FA 0.0.0.0 (the ASBR path), so FRR resolves via us.
docker exec "$R2" vtysh -c "configure terminal" -c "ip route $OUR_STATIC $R1_IP"
wait_in "$R2" "our ospfd originated the external LSA" 20 \
    "grep 'external LSA originated' $OUR_OSPFD_LOG | grep -q '$OUR_STATIC'"
# NB: the FILTERED 'database external' form prints the DETAIL view
# (one field per line); the summary table's one-line rows come from
# the unfiltered 'database' command.
wait_in "$R1" "FRR holds our external LSA" 30 \
    "vtysh -c 'show ip ospf database' | grep '$OUR_RID' | grep -q '${OUR_STATIC%/*}'"
# FRR's RIB is rousterd-backed (no FRR zebra): the proof is the
# kernel route through rousterd, via OUR address.
wait_in "$R1" "$OUR_STATIC in r1 kernel via OSPF" 30 \
    "ip route show proto ospf | grep -q '$OUR_STATIC'"
docker exec "$R1" sh -c "ip route show proto ospf | grep '$OUR_STATIC'" | grep -q "via $R2_IP" \
    || fail "FRR's OSPF route for $OUR_STATIC does not point at us ($R2_IP)"

echo "==> REDIST-IN: FRR's static -> FRR type-5 -> our §16.4 -> r2 kernel"
# A blackhole static: FRR then sets the type-5 forwarding address to
# 0.0.0.0 (a via-us nexthop would set FA = our address, a loop in
# this two-router topology), so our §16.4 resolves the ASBR path
# through the p2p adjacency.
docker exec "$R1" vtysh -c "configure terminal" -c "ip route $FRR_STATIC blackhole"
wait_in "$R1" "FRR originated its external LSA" 30 \
    "vtysh -c 'show ip ospf database' | grep '$FRR_RID' | grep -q '${FRR_STATIC%/*}'"
wait_in "$R2" "our ospfd installed FRR's external route" 30 \
    "grep 'OSPF route installed' $OUR_OSPFD_LOG | grep -q '$FRR_STATIC'"
wait_in "$R2" "r2 rousterd exported it to the kernel" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$FRR_STATIC'"
wait_in "$R2" "$FRR_STATIC in r2 kernel proto ospf via FRR" 30 \
    "ip route show proto ospf | grep '$FRR_STATIC' | grep -q 'via $R1_IP'"

echo "==> SOAK: 30 s adjacency/route stability"
sleep 30
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor' | grep -q Full" \
    || fail "FRR adjacency dropped during soak"
docker exec "$R2" sh -c "grep -q 'adjacency FULL' $OUR_OSPFD_LOG" \
    || fail "our adjacency dropped during soak"
docker exec "$R2" sh -c "ip route show proto ospf | grep -q '$FRR_STATIC'" \
    || fail "external route lost during soak"
[ "$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")" = "$R1_SESSIONS" ] \
    || fail "r1 saw a zapi reconnect during the soak"
[ "$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")" = "$R2_SESSIONS" ] \
    || fail "r2 saw a zapi reconnect during the soak"
docker exec "$R1" sh -c "pidof rousterd mgmtd staticd ospfd" >/dev/null \
    || fail "an r1 daemon died during the soak"
docker exec "$R2" sh -c "pidof rousterd mgmtd staticd rouster-ospfd" >/dev/null \
    || fail "an r2 daemon died during the soak"

echo "==> final state"
# No `show ip route` here: FRR's zebra is rousterd (no vtysh zebra
# view) — the kernel tables are the truth.
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor'; echo ---; ip route show proto ospf"
docker exec "$R2" sh -c "ip route show proto ospf"

echo "ospf-frr interop: PASS"
