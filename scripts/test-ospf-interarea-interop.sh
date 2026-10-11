#!/usr/bin/env bash
# OSPF inter-area interop (N2 M4): Rouster's ospfd as an area border
# router between two REAL FRR 10.2.2 ospfd routers — the §12.4.3
# summary duties and the §16.2/§16.4 inter-area walk, on the wire.
#
#   net0 (area 0.0.0.0)              net1 (area 0.0.0.1)
#   r1 (FRR ABR) ---- r2 (rouster ABR) ---- r3 (FRR, ASBR)
#     eth0                eth0    eth1          eth0
#     dummy0 (area 2)
#
#   r1: FRR ospfd, ABR — backbone + a dummy area 2 (10.99.0.0/24):
#       originates FRR's type-3 into area 0.
#   r2: rousterd + OUR ospfd, the ABR under test — area 0 + area 1.
#   r3: FRR ospfd internal to area 1, redistributing a blackhole
#       static (ASBR).
#
# Machine checks (script exit 0):
#   - ADJACENCY: r1-r2 Full (area 0) and r2-r3 Full (area 1), both
#     directions.
#   - OUR-TYPE-3: r1's area-0 database holds OUR summary-LSA for
#     net1's subnet; r1's KERNEL routes it proto ospf via us (the
#     O IA proof — an area-1 route arriving via summary-LSAs and
#     landing in the peer's kernel through rousterd).
#   - FRR-TYPE-3: r1's area-2 dummy subnet reaches OUR §16.2 — our
#     log installs it and OUR kernel carries it proto ospf via r1.
#   - TYPE-4-EXTERNAL: r3's static (type-5, AS-scoped) reaches our
#     kernel via area 1; WE originate the type-4 for r3 into area 0
#     (r1's `show ip ospf database asbr-summary` carries it) and r1
#     resolves the external through us (kernel proto ospf via r2).
#   - SOAK: 20 s — adjacencies, routes, and both ABR roles hold.
#
# Never pulls images (frr-testbed:10.2.2 cached; `docker network
# create` is local); caps as the ospf family; self-cleaning (nets +
# containers); quarantine under away/2026-10-11/night/quarantine/n2/
# interarea/ on success AND failure (absolute env-overridable,
# repo-relative default — the public-repo rule).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf-iar-r1
R2=ospf-iar-r2
R3=ospf-iar-r3
NET0=ospf-iar-net0
NET1=ospf-iar-net1
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
FRR_OSPFD_LOG=/tmp/ospfd.log
OUR_OSPFD_LOG=/var/log/rouster-ospfd.log
R1_RID=10.255.1.1
R2_RID=10.255.2.1
R3_RID=10.255.3.1
R3_STATIC=203.0.113.0/24      # r3's blackhole static -> type-5 -> both
DUMMY=10.99.0.0/24            # r1's area-2 dummy -> FRR type-3
QUARANTINE="${ROUSTER_OSPF_IAR_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/n2/interarea}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

ip_of() { # container iface -> "addr len"
    docker exec "$1" sh -c "ip -4 addr show dev $2" | sed -n 's/.*inet \([0-9.]*\)\/\([0-9]*\) .*/\1 \2/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE"/{r1,r2,r3}
    for side in r1 r2 r3; do
        name="ospf-iar-$side"
        docker exec "$name" sh -c "ip -4 addr; echo ---; ip route show; echo ---; ip route show proto ospf" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database'" \
            > "$QUARANTINE/$side/ospf.txt" 2>&1 || true
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker cp "$name:$OUR_OSPFD_LOG" "$QUARANTINE/$side/rouster-ospfd.log" 2>/dev/null || true
        docker cp "$name:$FRR_OSPFD_LOG" "$QUARANTINE/$side/frr-ospfd.log" 2>/dev/null || true
        docker cp "$name:$FRR_CONF" "$QUARANTINE/$side/frr.conf" 2>/dev/null || true
        docker exec "$name" sh -c "cat /etc/rouster-ospfd.conf" \
            > "$QUARANTINE/$side/rouster-ospfd.conf" 2>&1 || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    for name in "$R1" "$R2" "$R3"; do
        echo "--- $name ospfd tails ---" >&2
        docker exec "$name" sh -c "tail -15 $FRR_OSPFD_LOG 2>/dev/null; tail -20 $OUR_OSPFD_LOG 2>/dev/null" >&2 || true
        echo "--- $name ospf neighbor ---" >&2
        docker exec "$name" sh -c "vtysh -c 'show ip ospf neighbor'" >&2 || true
        echo "--- $name kernel ospf routes ---" >&2
        docker exec "$name" sh -c "ip route show proto ospf" >&2 || true
    done
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

cleanup() {
    capture
    docker rm -f "$R1" "$R2" "$R3" >/dev/null 2>&1 || true
    docker network rm "$NET0" "$NET1" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "$R1" "$R2" "$R3" >/dev/null 2>&1 || true
docker network rm "$NET0" "$NET1" >/dev/null 2>&1 || true

echo "==> building rousterd + ospfd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin ospfd

echo "==> two bridges: $NET0 (area 0), $NET1 (area 1)"
docker network create "$NET0" >/dev/null
docker network create "$NET1" >/dev/null

echo "==> containers (no pull)"
docker run -d --name "$R1" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --network "$NET0" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$R2" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --network "$NET0" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$R3" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --network "$NET1" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker network connect "$NET1" "$R2"
for name in "$R1" "$R2" "$R3"; do
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/ospfd" "$name:/usr/local/bin/rouster-ospfd"
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
done

read -r R1_IP R1_LEN <<< "$(ip_of "$R1" eth0)"
read -r R2_IP0 R2_LEN0 <<< "$(ip_of "$R2" eth0)"
read -r R2_IP1 R2_LEN1 <<< "$(ip_of "$R2" eth1)"
read -r R3_IP R3_LEN <<< "$(ip_of "$R3" eth0)"
[ -n "$R1_IP" ] && [ -n "$R2_IP0" ] && [ -n "$R2_IP1" ] && [ -n "$R3_IP" ] || fail "no addresses"
NET0_SUBNET=$(docker exec "$R1" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
NET1_SUBNET=$(docker exec "$R3" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
echo "==> net0=$NET0_SUBNET (r1=$R1_IP r2=$R2_IP0)  net1=$NET1_SUBNET (r2=$R2_IP1 r3=$R3_IP)"

echo "==> resident rousterd (zebra) in all three"
for name in "$R1" "$R2" "$R3"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
    wait_in "$name" "$name rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
done

echo "==> r1: dummy area-2 iface + FRR ospfd (mgmtd/staticd ride along)"
docker exec "$R1" sh -c "ip link add dummy0 type dummy; ip link set dummy0 up; ip addr add 10.99.0.1/24 dev dummy0"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
docker exec "$R1" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
docker exec "$R3" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R3" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
docker exec "$R3" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
wait_in "$R1" "r1 FRR daemons up" 30 "pidof mgmtd staticd ospfd"
wait_in "$R3" "r3 FRR daemons up" 30 "pidof mgmtd staticd ospfd"

echo "==> r2: OUR ospfd as the ABR (area 0 on eth0, area 1 on eth1)"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router ospf' \
  ' router-id $R2_RID' \
  ' area 0.0.0.0' \
  '  interface eth0' \
  '   address $R2_IP0/$R2_LEN0' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' area 0.0.0.1' \
  '  interface eth1' \
  '   address $R2_IP1/$R2_LEN1' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' redistribute static' \
  > /etc/rouster-ospfd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R2" "our ospfd is up" 10 "pidof rouster-ospfd"

echo "==> FRR configs (vtysh -b, retried past the zebra-view race)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-iar-r1' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R1_RID' \
  ' network $NET0_SUBNET area 0.0.0.0' \
  ' network $DUMMY area 0.0.0.2' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R3" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-iar-r3' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R3_RID' \
  ' network $NET1_SUBNET area 0.0.0.1' \
  ' redistribute static' \
  'line vty' \
  > $FRR_CONF"
for name in "$R1" "$R3"; do
    APPLIED=0
    for _ in $(seq 1 10); do
        docker exec "$name" vtysh -b >/dev/null 2>&1 || true
        sleep 2
        if docker exec "$name" sh -c "vtysh -c 'show ip ospf interface eth0' 2>/dev/null | grep -qi 'point-to-point'"; then
            APPLIED=1
            break
        fi
    done
    [ "$APPLIED" = 1 ] || fail "FRR ospf config never applied on $name"
done
# r3's ASBR static (blackhole pins FA to 0.0.0.0 — the W2-e note).
docker exec "$R3" vtysh -c "configure terminal" -c "ip route $R3_STATIC blackhole"

echo "==> ADJACENCY: r1-r2 (area 0) and r2-r3 (area 1) Full, both ways"
wait_in "$R1" "r1 (FRR) sees r2 Full" 90 "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full"
wait_in "$R3" "r3 (FRR) sees r2 Full" 90 "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full"
wait_in "$R2" "our ABR logged both adjacencies FULL" 90 \
    "grep -c 'adjacency FULL' $OUR_OSPFD_LOG | grep -q 2"
# The B-bit: our ABR status shows in r1's detail view of our
# router-LSA (the summary table carries no flags).
wait_in "$R1" "r1 sees our router-LSA as an area border router" 30 \
    "vtysh -c 'show ip ospf database router $R2_RID' | grep -q ': ABR'"

echo "==> OUR-TYPE-3: r1's area-0 database holds our summary for $NET1_SUBNET"
# NB: the FILTERED 'database summary' prints the detail form (one
# field per line — the W2-e finding); the unfiltered table carries
# the one-line rows.
wait_in "$R1" "r1 holds OUR type-3 for the area-1 network" 60 \
    "vtysh -c 'show ip ospf database' | grep '$R2_RID' | grep -q '$(echo "$NET1_SUBNET" | cut -d/ -f1)'"
wait_in "$R1" "r1's KERNEL routes it proto ospf via us (O IA)" 30 \
    "ip route show proto ospf | grep '$NET1_SUBNET' | grep -q 'via $R2_IP0'"

echo "==> FRR-TYPE-3: r1's area-2 $DUMMY reaches our §16.2"
wait_in "$R2" "our ABR installed the inter-area route" 60 \
    "grep 'OSPF route installed' $OUR_OSPFD_LOG | grep -q '10.99.0.0/24'"
wait_in "$R2" "our kernel carries it proto ospf via r1" 30 \
    "ip route show proto ospf | grep '10.99.0.0/24' | grep -q 'via $R1_IP'"

echo "==> TYPE-4-EXTERNAL: r3's static through our ABR duties"
# Our side: the type-5 (AS-scoped) reached us through area 1.
wait_in "$R2" "our kernel carries r3's static via r3 (area 1)" 60 \
    "ip route show proto ospf | grep '$R3_STATIC' | grep -q 'via $R3_IP'"
# Our type-4 for r3 in r1's area-0 database.
wait_in "$R1" "r1 holds OUR type-4 (asbr-summary) for r3" 60 \
    "vtysh -c 'show ip ospf database' | grep '$R3_RID' | grep -q '$R2_RID'"
# r1 resolves r3's external through our type-4 — kernel via us.
wait_in "$R1" "r1's kernel routes r3's static proto ospf via us" 60 \
    "ip route show proto ospf | grep '$R3_STATIC' | grep -q 'via $R2_IP0'"

echo "==> SOAK: 20 s"
sleep 20
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full" \
    || fail "r1-r2 adjacency dropped during the soak"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full" \
    || fail "r2-r3 adjacency dropped during the soak"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "ip route show proto ospf | grep -q '$R3_STATIC'" \
        || fail "$name lost the external route during the soak"
done
docker exec "$R2" sh -c "pidof rousterd rouster-ospfd" >/dev/null \
    || fail "one of our daemons died during the soak"
docker exec "$R1" sh -c "pidof rousterd mgmtd staticd ospfd" >/dev/null \
    || fail "an r1 daemon died during the soak"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database summary'; echo ---; vtysh -c 'show ip ospf database asbr-summary'; echo ---; ip route show proto ospf"
docker exec "$R2" sh -c "ip route show proto ospf"
docker exec "$R3" sh -c "ip route show proto ospf"

echo "ospf-interarea interop: PASS"
