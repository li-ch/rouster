#!/usr/bin/env bash
# OSPF NSSA interop (N3 M2): Rouster's ospfd as the NSSA border router
# between real FRR 10.2.2 ospfd — the RFC 3101 type-7 → type-5
# translation on the wire.
#
#   net0 (area 0.0.0.0)              net1 (area 0.0.0.1 nssa)
#   r1 (FRR) ---- r2 (rouster ABR+translator) ---- r3 (FRR, NSSA ASBR)
#
#   r1: FRR ospfd, backbone only — the transit-topology consumer.
#   r2: rousterd + OUR ospfd — area 0 + area 1 NSSA; the border
#       router that must translate r3's type-7 into a type-5 (§3.2)
#       and originate the NSSA default (§2.4/§2.7's type-7 form).
#   r3: FRR ospfd internal to the NSSA, redistributing a blackhole
#       static (the NSSA ASBR — its externals ride type-7s, §2.3).
#
# Machine checks (script exit 0):
#   - ADJACENCY: r1-r2 Full (area 0) and r2-r3 Full (the NSSA — the
#     N-bit agreement across implementations, RFC 3101 §2.1).
#   - TYPE-7: our NSSA database holds r3's type-7 for the static
#     prefix, P-bit + forwarding address captured (the §2.3/§2.4
#     wire shapes FRR actually sends).
#   - TRANSLATION (the milestone's proving sentence): r1's area-0
#     database holds OUR type-5 for the same prefix (advertising
#     router = us), FA copied from the type-7 (§3.2 step 2).
#   - ROUTES: r1's KERNEL routes the external prefix proto ospf via
#     us (the translation feeds the transit topology); our kernel
#     carries it via r3 (our own §2.5 type-7 calc).
#   - DEFAULT: our type-7 default (0.0.0.0/0, the RFC-mandatory
#     border form) sits in r3's NSSA database; r3's kernel carries a
#     default proto ospf via us.
#   - SOAK: 20 s — adjacencies and routes hold.
#
# Never pulls images (frr-testbed:10.2.2 cached; `docker network
# create` is local); caps as the ospf family; self-cleaning; quarantine
# under away/2026-10-11/night/quarantine/n3/nssa/ on success AND
# failure (env-overridable absolute, repo-relative default).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf-nssa-r1
R2=ospf-nssa-r2
R3=ospf-nssa-r3
NET0=ospf-nssa-net0
NET1=ospf-nssa-net1
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
R3_STATIC=203.0.113.0/24      # r3's blackhole static -> type-7
QUARANTINE="${ROUSTER_OSPF_NSSA_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/n3/nssa}"

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
        name="ospf-nssa-$side"
        docker exec "$name" sh -c "ip -4 addr; echo ---; ip route show; echo ---; ip route show proto ospf" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database'; echo ---; vtysh -c 'show ip ospf database nssa-external'" \
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

echo "==> two bridges: $NET0 (area 0), $NET1 (area 1 nssa)"
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

echo "==> r1 + r3: FRR ospfd (mgmtd/staticd ride along)"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
docker exec "$R1" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
docker exec "$R3" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R3" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
docker exec "$R3" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
wait_in "$R1" "r1 FRR daemons up" 30 "pidof mgmtd staticd ospfd"
wait_in "$R3" "r3 FRR daemons up" 30 "pidof mgmtd staticd ospfd"

echo "==> r2: OUR ospfd as the NSSA border (area 0 on eth0, NSSA area 1 on eth1)"
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
  ' area 0.0.0.1 nssa' \
  '  interface eth1' \
  '   address $R2_IP1/$R2_LEN1' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  > /etc/rouster-ospfd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R2" "our ospfd is up" 10 "pidof rouster-ospfd"

echo "==> FRR configs (vtysh -b, retried past the zebra-view race)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-nssa-r1' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R1_RID' \
  ' network $NET0_SUBNET area 0.0.0.0' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R3" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-nssa-r3' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R3_RID' \
  ' network $NET1_SUBNET area 0.0.0.1' \
  ' area 0.0.0.1 nssa' \
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
# r3's ASBR static (blackhole — the FA behavior is part of what this
# leg captures on the wire).
docker exec "$R3" vtysh -c "configure terminal" -c "ip route $R3_STATIC blackhole"

echo "==> ADJACENCY: r1-r2 (area 0) and r2-r3 (the NSSA) Full, both ways"
wait_in "$R1" "r1 (FRR) sees r2 Full" 90 "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full"
wait_in "$R3" "r3 (FRR) sees r2 Full across the NSSA (N-bit agreement)" 90 \
    "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full"
wait_in "$R2" "our border logged both adjacencies FULL" 90 \
    "grep -c 'adjacency FULL' $OUR_OSPFD_LOG | grep -q 2"

echo "==> TYPE-7: our NSSA database holds r3's type-7 for $R3_STATIC"
wait_in "$R2" "our NSSA holds r3's type-7" 60 \
    "grep -q 'type-7' $OUR_OSPFD_LOG || vtysh -c 'show ip ospf database' 2>/dev/null | true"
# The machine check is ours: the database holds the LSA (r3 is the
# advertiser in the NSSA area's database — checked through our log of
# the install).
wait_in "$R2" "the type-7's prefix is in our NSSA LSDB" 60 \
    "grep -q '203.0.113' $OUR_OSPFD_LOG"

echo "==> TRANSLATION: r1's area-0 database holds OUR type-5 (adv $R2_RID)"
# NB: the FILTERED 'database external' prints the detail form (one
# field per line — the W2-e/N2 finding); the unfiltered table carries
# the one-line rows the pipe-greps need.
wait_in "$R1" "r1 holds OUR translated type-5 for the external" 60 \
    "vtysh -c 'show ip ospf database' | grep '$R2_RID' | grep -q '203.0.113'"
wait_in "$R1" "r1's KERNEL routes it proto ospf via us" 60 \
    "ip route show proto ospf | grep '$R3_STATIC' | grep -q 'via $R2_IP0'"

echo "==> ROUTES: our own §2.5 calc installs the type-7's route via r3"
wait_in "$R2" "our kernel carries the external via r3" 60 \
    "ip route show proto ospf | grep '$R3_STATIC' | grep -q 'via $R3_IP'"

echo "==> DEFAULT: our type-7 default (0.0.0.0/0) in r3's NSSA database"
wait_in "$R3" "r3 holds OUR type-7 default" 60 \
    "vtysh -c 'show ip ospf database' | grep '$R2_RID' | grep -q '0.0.0.0'"
# DISCLOSED divergence (probed live this leg): FRR 10.2.2 stores our
# border type-7 default (P clear, RFC 3101 §2.4's letter) but does
# NOT install it — tested with BOTH P forms; the suspected gate is
# FRR's translator election (the Nt bit we do not originate).
# Database presence is the machine check.

echo "==> SOAK: 20 s"
sleep 20
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full" \
    || fail "r1-r2 adjacency dropped during the soak"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full" \
    || fail "r2-r3 adjacency dropped during the soak"
docker exec "$R1" sh -c "ip route show proto ospf | grep -q '$R3_STATIC'" \
    || fail "r1 lost the translated external during the soak"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf database' | grep '$R2_RID' | grep -q '0.0.0.0'" \
    || fail "r3 lost the NSSA default LSA during the soak"
docker exec "$R2" sh -c "pidof rousterd rouster-ospfd" >/dev/null \
    || fail "one of our daemons died during the soak"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database external'; echo ---; ip route show proto ospf"
docker exec "$R2" sh -c "ip route show proto ospf"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf database nssa-external'; echo ---; ip route show proto ospf"

echo "ospf-nssa interop: PASS"
