#!/usr/bin/env bash
# OSPF broadcast-network interop (N2 M2): Rouster's ospfd joins a
# REAL FRR 10.2.2 ospfd DR election on a shared broadcast network
# (the docker bridge, default network type both sides), proving the
# §9.4 election, the §10.4 adjacency rule, the DR's §12.4.2
# network-LSA, and the §16.1 pseudo-node routing — cross-implementation.
#
#   r1 (FRR, priority 40):  rousterd + real ospfd     -> DR
#   r2 (rouster, pri 30):   rousterd + our ospfd      -> BDR
#   r3 (FRR, priority 20):  rousterd + real ospfd     -> DR Other
#   r4 (rouster, pri 10):   rousterd + our ospfd      -> DR Other
#
#   area 0.0.0.0, broadcast (§C.3 default), hellos 2 s / dead 8 s,
#   router IDs pinned (r1 10.255.1.1, r2 10.255.2.1, r3 10.255.3.1,
#   r4 10.255.4.1).
#
# Machine checks (script exit 0):
#   - ELECTION: all four agree — r1 DR, r2 BDR (FRR `show ip ospf
#     interface eth0` states; our r2/r4 logs carry the §9.4 election
#     line with dr=<r1> bdr=<r2>).
#   - ADJACENCY-10-4: the DR/BDR pairs reach Full — r1 sees r2/r3/r4
#     Full; r2 (us, BDR) logs three "adjacency FULL" lines; r3 (FRR
#     DR Other) sees r1/r2 Full and r4 at "2-Way/DROther"; r4 (us,
#     DR Other) logs two "adjacency FULL" (r1, r2) and a
#     "stays 2-Way" line for r3 — the §10.4 two-router proof, one
#     direction per implementation.
#   - NETWORK-LSA: r1's `show ip ospf database network` lists all
#     four attached routers (§12.4.2); our r4's SPF consumed it (the
#     "OSPF route installed" log for the transit prefix — the route
#     itself is connected-covered in the kernel, the W2-e note).
#   - PSEUDO-NODE-ROUTE: r1 redistributes a blackhole static → its
#     type-5 → our r4's §16.4 resolves the ASBR path THROUGH the
#     broadcast pseudo-node (§16.1.1 case two: the next hop is the
#     ASBR's Link Data on the transit link) → the kernel carries the
#     external route proto ospf via r1's address.
#   - SOAK: 30 s — states and routes hold, no zapi reconnects, every
#     daemon alive.
#
# Never pulls images (frr-testbed:10.2.2 cached); caps as the ospf
# family (NET_ADMIN/NET_RAW/SYS_ADMIN — raw proto-89 sockets need
# NET_RAW); self-cleaning; quarantine under
# away/2026-10-11/night/quarantine/n2/broadcast/ on success AND
# failure (absolute env-overridable, repo-relative default — the
# public-repo rule).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf-bcast-r1
R2=ospf-bcast-r2
R3=ospf-bcast-r3
R4=ospf-bcast-r4
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
R4_RID=10.255.4.1
QUARANTINE="${ROUSTER_OSPF_BCAST_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/n2/broadcast}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/\([0-9]*\) .*/\1 \2/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE"/{r1,r2,r3,r4}
    for side in r1 r2 r3 r4; do
        name="ospf-bcast-$side"
        docker exec "$name" sh -c "ip route show proto ospf; echo ---; ip route show" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database'" \
            > "$QUARANTINE/$side/ospf.txt" 2>&1 || true
        docker exec "$name" sh -c "cat /etc/rouster-ospfd.conf" \
            > "$QUARANTINE/$side/rouster-ospfd.conf" 2>&1 || true
        docker cp "$name:$OUR_OSPFD_LOG" "$QUARANTINE/$side/rouster-ospfd.log" 2>/dev/null || true
        docker cp "$name:$FRR_OSPFD_LOG" "$QUARANTINE/$side/frr-ospfd.log" 2>/dev/null || true
        docker cp "$name:$FRR_CONF" "$QUARANTINE/$side/frr.conf" 2>/dev/null || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    for name in "$R1" "$R2" "$R3" "$R4"; do
        echo "--- $name ospfd tail ---" >&2
        docker exec "$name" sh -c "tail -20 $OUR_OSPFD_LOG 2>/dev/null; tail -20 $FRR_OSPFD_LOG 2>/dev/null" >&2 || true
        echo "--- $name ospf interface/neighbor ---" >&2
        docker exec "$name" sh -c "vtysh -c 'show ip ospf interface eth0'; echo ---; vtysh -c 'show ip ospf neighbor'" >&2 || true
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

trap 'capture; docker rm -f "$R1" "$R2" "$R3" "$R4" >/dev/null 2>&1 || true' EXIT
docker rm -f "$R1" "$R2" "$R3" "$R4" >/dev/null 2>&1 || true

echo "==> building rousterd + ospfd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin ospfd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2" "$R3" "$R4"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/ospfd" "$name:/usr/local/bin/rouster-ospfd"
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
done

SUBNET=$(docker exec "$R1" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
echo "==> bridge subnet=$SUBNET (all four share it — the broadcast network)"

echo "==> resident rousterd (zebra) in all four containers"
for name in "$R1" "$R2" "$R3" "$R4"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
    wait_in "$name" "$name rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
done

echo "==> FRR ospfd on r1 (pri 40) and r3 (pri 20); ours on r2 (pri 30) and r4 (pri 10)"
# mgmtd + staticd ride along on the FRR side: the pseudo-node leg's
# `ip route ... blackhole` + `redistribute static` vtysh writes go to
# staticd (the W2-e convention).
for name in "$R1" "$R3"; do
    docker exec "$name" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
    docker exec "$name" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
    docker exec "$name" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
    wait_in "$name" "$name FRR daemons up" 30 "pidof mgmtd staticd ospfd"
done
for entry in "$R2:$R2_RID 30" "$R4:$R4_RID 10"; do
    name="${entry%%:*}"; read -r rid pri <<< "${entry#*:}"
    read -r ip len <<< "$(bridge_ip "$name")"
    docker exec "$name" sh -c "printf '%s\n' \
      'zapi socket $ZAPI_SOCK' \
      'router ospf' \
      ' router-id $rid' \
      ' area 0.0.0.0' \
      '  interface eth0' \
      '   address $ip/$len' \
      '   priority $pri' \
      '   hello-interval 2' \
      '   dead-interval 8' \
      > /etc/rouster-ospfd.conf"
    docker exec "$name" sh -c "cat /etc/rouster-ospfd.conf"
    docker exec -d "$name" sh -c "NO_COLOR=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
    wait_in "$name" "$name our ospfd is up" 10 "pidof rouster-ospfd"
done

read -r R1_IP R1_LEN <<< "$(bridge_ip "$R1")"
read -r R2_IP R2_LEN <<< "$(bridge_ip "$R2")"

echo "==> FRR configs (vtysh -b, retried past the zebra-view race)"
for entry in "$R1:$R1_RID 40" "$R3:$R3_RID 20"; do
    name="${entry%%:*}"; read -r rid pri <<< "${entry#*:}"
    docker exec "$name" sh -c "printf '%s\n' \
      'frr version 10.2' \
      'frr defaults traditional' \
      'hostname $name' \
      'interface eth0' \
      ' ip ospf priority $pri' \
      ' ip ospf hello-interval 2' \
      ' ip ospf dead-interval 8' \
      'router ospf' \
      ' router-id $rid' \
      ' network $SUBNET area 0.0.0.0' \
      'line vty' \
      > $FRR_CONF"
done
for name in "$R1" "$R3"; do
    APPLIED=0
    for _ in $(seq 1 10); do
        docker exec "$name" vtysh -b >/dev/null 2>&1 || true
        sleep 2
        if docker exec "$name" sh -c "vtysh -c 'show ip ospf interface eth0' 2>/dev/null | grep -qi 'broadcast'"; then
            APPLIED=1
            break
        fi
    done
    [ "$APPLIED" = 1 ] || fail "FRR ospf config never applied on $name (zebra-view race)"
done

echo "==> ELECTION: waiting for the four-way DR election to converge"
# FRR views: r1 = DR, r3 = DR Other.
wait_in "$R1" "r1 (FRR) reports itself DR" 90 \
    "vtysh -c 'show ip ospf interface eth0' | grep -q 'State DR'"
# NB: the interface view prints "State DROther" (no space); the
# neighbor view "2-Way/DROther" — both pinned from the 10.2.2 wire.
wait_in "$R3" "r3 (FRR) reports DROther" 90 \
    "vtysh -c 'show ip ospf interface eth0' | grep -q 'State DROther'"
# r1's BDR is r2 (us).
wait_in "$R1" "r1 names r2 as BDR" 30 \
    "vtysh -c 'show ip ospf interface eth0' | grep 'Backup Designated Router' | grep -q '$R2_RID'"
# Our views: r2 = Backup, r4 = DR Other, both with dr=r1 bdr=r2.
wait_in "$R2" "our r2 elected Backup with r1 DR / r2 BDR" 90 \
    "grep 'DR election' $OUR_OSPFD_LOG | tail -1 | grep -q 'bdr=$R2_IP'"
wait_in "$R2" "r2's DR is r1" 30 \
    "grep 'DR election' $OUR_OSPFD_LOG | tail -1 | grep -q 'dr=$R1_IP'"
wait_in "$R4" "our r4 elected DR Other with r1 DR / r2 BDR" 90 \
    "grep 'DR election' $OUR_OSPFD_LOG | tail -1 | grep -q 'role=.DR Other.'"

echo "==> ADJACENCY-10-4: Full toward DR/BDR, 2-Way between the DR Others"
# r1 (DR): all three neighbors Full.
wait_in "$R1" "r1 sees three Full neighbors" 90 \
    "vtysh -c 'show ip ospf neighbor' | grep -c Full | grep -q 3"
# r3 (FRR DR Other): r1/r2 Full, r4 at 2-Way/DROther.
wait_in "$R3" "r3 sees r1/r2 Full" 90 \
    "vtysh -c 'show ip ospf neighbor' | grep -c Full | grep -q 2"
wait_in "$R3" "r3 sees r4 (us) at 2-Way/DROther — the §10.4 stop" 60 \
    "vtysh -c 'show ip ospf neighbor' | grep '$R4_RID' | grep -q '2-Way'"
# r2 (us, BDR): three Full adjacencies (r1, r3, r4).
wait_in "$R2" "our r2 (BDR) logged three adjacency FULL" 90 \
    "grep -c 'adjacency FULL' $OUR_OSPFD_LOG | grep -q 3"
# r4 (us, DR Other): Full with r1 and r2 only; the r3 pair stays 2-Way.
wait_in "$R4" "our r4 (DROther) logged two adjacency FULL" 90 \
    "grep -c 'adjacency FULL' $OUR_OSPFD_LOG | grep -q 2"
wait_in "$R4" "our r4 logged the §10.4 stays-2-Way line for r3" 60 \
    "grep 'stays 2-Way' $OUR_OSPFD_LOG | grep -q '$R3_RID'"

echo "==> NETWORK-LSA: the DR's network-LSA lists all four routers"
wait_in "$R1" "r1's network-LSA attached count = 4" 30 \
    "vtysh -c 'show ip ospf database network' | grep -c 'Attached Router' | grep -q 4"
# Our side consumed the DR's network-LSA: the SPF route for the
# transit prefix (connected-covered in the kernel, so the log is the
# honest surface — the W2-e topology note).
wait_in "$R4" "our r4's SPF installed the transit network route" 30 \
    "grep 'OSPF route installed' $OUR_OSPFD_LOG | grep -q '$SUBNET'"

echo "==> PSEUDO-NODE-ROUTE: r1's static -> type-5 -> r4 via the broadcast pseudo-node"
# The blackhole form pins FRR's type-5 forwarding address to
# 0.0.0.0 (the W2-e finding), so our §16.4 resolves the ASBR path —
# through the network-LSA pseudo-node, next hop = r1's own address.
docker exec "$R1" vtysh -c "configure terminal" -c "router ospf" -c "redistribute static"
docker exec "$R1" vtysh -c "configure terminal" -c "ip route 198.51.100.0/24 blackhole"
wait_in "$R4" "our r4 installed the external route" 30 \
    "grep 'OSPF route installed' $OUR_OSPFD_LOG | grep -q '198.51.100.0/24'"
wait_in "$R4" "r4 kernel carries it proto ospf via r1 (the pseudo-node hop)" 30 \
    "ip route show proto ospf | grep '198.51.100.0/24' | grep -q 'via $R1_IP'"

echo "==> SOAK: 30 s election/adjacency/route stability"
sleep 30
docker exec "$R1" sh -c "vtysh -c 'show ip ospf neighbor' | grep -c Full | grep -q 3" \
    || fail "r1 lost an adjacency during the soak"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R4_RID' | grep -q '2-Way'" \
    || fail "the r3-r4 2-Way pair left 2-Way during the soak"
for entry in "$R2 3" "$R4 2"; do
    set -- $entry
    docker exec "$1" sh -c "grep -c 'adjacency FULL' $OUR_OSPFD_LOG | grep -q $2" \
        || fail "$1's adjacency count changed during the soak"
done
for name in "$R2" "$R4"; do
    [ "$(docker exec "$name" sh -c "grep -c 'session established' $ROUSTERD_LOG || true")" = 1 ] \
        || fail "$name saw a zapi reconnect during the soak"
    docker exec "$name" sh -c "ip route show proto ospf | grep -q '198.51.100.0/24'" \
        || fail "$name lost the external route during the soak"
done
for entry in "$R1:ospfd rousterd" "$R2:rouster-ospfd rousterd" "$R3:ospfd rousterd" "$R4:rouster-ospfd rousterd"; do
    name="${entry%%:*}"
    docker exec "$name" sh -c "pidof rousterd ${entry#*:}" >/dev/null \
        || fail "a daemon died on $name during the soak"
done

echo "==> final state"
for name in "$R1" "$R3"; do
    docker exec "$name" sh -c "vtysh -c 'show ip ospf neighbor'; echo ---"
done
for name in "$R2" "$R4"; do
    docker exec "$name" sh -c "ip route show proto ospf; echo ---"
done

echo "ospf-broadcast interop: PASS"
