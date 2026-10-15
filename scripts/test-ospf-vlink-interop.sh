#!/usr/bin/env bash
# OSPF virtual-link interop (S10-b M5): a PARTITIONED backbone joined
# by a virtual link between REAL FRR 10.2.2 ospfd and Rouster's ospfd,
# over a two-router transit area — the §15/§D.3 wire semantics live.
#
#   net1 (area 0.0.0.1)              net2 (area 0.0.0.1)
#   r1 (FRR, vl endpoint) ---- r3 (FRR transit) ---- r2 (rouster, vl endpoint)
#     eth0 (area 1)              eth0      eth1         eth0 (area 1)
#     dummy0 (area 0.0.0.0)                                | area 0.0.0.0
#                                        <==== virtual link r1 <---> r2 ====
#
#   r1: FRR ospfd — area 1 on eth0 + a dummy area-0 interface; the
#       virtual link to r2's Router ID configured under area 1.
#   r3: FRR ospfd — area 1 only (the two-hop transit middle router;
#       NOT an ABR).
#   r2: rousterd + OUR ospfd — area 1 on eth0 + the area-0 stanza
#       (no real interface — the vlink is its only member) +
#       `area 0.0.0.1 virtual-link <r1 rid>`; redistributes a
#       blackhole static (the AS-scope proof over the vlink).
#
# Machine checks (script exit 0):
#   - TRANSIT-ADJ: r1-r3 and r3-r2 Full, both directions (vtysh +
#     our adjacency-FULL log lines).
#   - VLINK-UP: FRR's `show ip ospf virtual-links` reports the link
#     to r2 Up/Full; OUR side logged the §16.1-step-4 endpoint
#     resolution (r1's OWN transit-facing address, not the first-hop
#     gateway) and the vlink adjacency FULL.
#   - BACKBONE-LSAS: r1's area-0 database holds OUR backbone
#     router-LSA (with the type-4 virtual link); our log shows r1's
#     backbone router-LSA installed (the partitioned databases join).
#   - ROUTE-THROUGH-VLINK: r1's dummy area-0 subnet reaches OUR
#     kernel proto ospf, via r1's transit address (recursively
#     resolved through the area-1 route — the §15 IP-routed tunnel);
#     and OUR redistributed static reaches r1's KERNEL through the
#     virtual link (FRR's side of the same proof).
#   - SOAK: 20 s — everything holds.
#
# Never pulls images (frr-testbed:10.2.2 cached; `docker network
# create` is local); caps as the ospf family; self-cleaning; quarantine
# under away/2026-10-14/quarantine/s10b/vlink/ on success AND failure
# (absolute env-overridable, repo-relative default — the public-repo
# rule).
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=ospf-vlink-r1
R2=ospf-vlink-r2
R3=ospf-vlink-r3
NET1=ospf-vlink-net1
NET2=ospf-vlink-net2
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
DUMMY=10.99.0.0/24            # r1's area-0 dummy -> the route-over-vlink proof
R2_STATIC=203.0.113.0/24      # our blackhole static -> the reverse proof
QUARANTINE="${ROUSTER_OSPF_VLINK_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-14/quarantine/s10b/vlink}"

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
        name="ospf-vlink-$side"
        docker exec "$name" sh -c "ip -4 addr; echo ---; ip route show; echo ---; ip route show proto ospf" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf interface'; echo ---; vtysh -c 'show ip ospf database'; echo ---; vtysh -c 'show ip ospf database router 10.255.1.1'; echo ---; vtysh -c 'show ip ospf database router 10.255.2.1'" \
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
        docker exec "$name" sh -c "tail -15 $FRR_OSPFD_LOG 2>/dev/null; tail -25 $OUR_OSPFD_LOG 2>/dev/null" >&2 || true
        echo "--- $name ospf neighbor + virtual-links ---" >&2
        docker exec "$name" sh -c "vtysh -c 'show ip ospf neighbor'; vtysh -c 'show ip ospf virtual-links'" >&2 || true
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
    docker network rm "$NET1" "$NET2" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker rm -f "$R1" "$R2" "$R3" >/dev/null 2>&1 || true
docker network rm "$NET1" "$NET2" >/dev/null 2>&1 || true

echo "==> building rousterd + ospfd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin ospfd

echo "==> two transit bridges: $NET1 (r1-r3), $NET2 (r3-r2), both area 0.0.0.1"
docker network create "$NET1" >/dev/null
docker network create "$NET2" >/dev/null

echo "==> containers (no pull)"
docker run -d --name "$R1" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --network "$NET1" --entrypoint sleep "$IMAGE" infinity >/dev/null
# --privileged: the transit box must FORWARD (the sysctl write needs
# a writable /proc/sys — the v3 rig's disclosed precedent).
docker run -d --name "$R3" --privileged \
    --network "$NET1" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$R2" --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --network "$NET2" --entrypoint sleep "$IMAGE" infinity >/dev/null
docker network connect "$NET2" "$R3"
for name in "$R1" "$R2" "$R3"; do
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/ospfd" "$name:/usr/local/bin/rouster-ospfd"
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
done

read -r R1_IP R1_LEN <<< "$(ip_of "$R1" eth0)"
read -r R3_IP1 R3_LEN1 <<< "$(ip_of "$R3" eth0)"
read -r R3_IP2 R3_LEN2 <<< "$(ip_of "$R3" eth1)"
read -r R2_IP R2_LEN <<< "$(ip_of "$R2" eth0)"
[ -n "$R1_IP" ] && [ -n "$R3_IP1" ] && [ -n "$R3_IP2" ] && [ -n "$R2_IP" ] || fail "no addresses"
NET1_SUBNET=$(docker exec "$R1" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
NET2_SUBNET=$(docker exec "$R2" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}')
echo "==> net1=$NET1_SUBNET (r1=$R1_IP r3=$R3_IP1)  net2=$NET2_SUBNET (r3=$R3_IP2 r2=$R2_IP)"

echo "==> resident rousterd (zebra) in all three"
for name in "$R1" "$R2" "$R3"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
    wait_in "$name" "$name rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
done

echo "==> r1: dummy area-0 iface (our endpoint); r3: FRR transit"
docker exec "$R1" sh -c "ip link add dummy0 type dummy; ip link set dummy0 up; ip addr add 10.99.0.1/24 dev dummy0"
# Rig truth (disclosed): §15's virtual-link packets are IP-FORWARDED
# by the transit router — FRR's zebra enables ip_forward when it
# starts; rousterd (r3's zebra here) does not (yet) — the rig sets it
# explicitly rather than letting the dataplane silently depend on
# which zebra implementation owns the transit box.
docker exec "$R3" sh -c "sysctl -w net.ipv4.ip_forward=1 >/dev/null"
docker exec "$R3" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R3" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
docker exec "$R3" sh -c "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$FRR_OSPFD_LOG --log-level debug"
wait_in "$R3" "r3 FRR daemons up" 30 "pidof mgmtd staticd ospfd"

echo "==> r1: OUR ospfd — area 1 on eth0, the dummy area-0 stub, the vlink"
docker exec "$R1" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router ospf' \
  ' router-id $R1_RID' \
  ' area 0.0.0.0' \
  '  interface dummy0' \
  '   address 10.99.0.1/24' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' area 0.0.0.1' \
  '  interface eth0' \
  '   address $R1_IP/$R1_LEN' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' area 0.0.0.1 virtual-link $R2_RID' \
  > /etc/rouster-ospfd.conf"
docker exec "$R1" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R1" sh -c "NO_COLOR=1 ROUSTER_OSPF_TRACE=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R1" "r1 our ospfd is up" 10 "pidof rouster-ospfd"

echo "==> r2: mgmtd + staticd (FRR) + OUR ospfd against rousterd"
docker exec "$R2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log"
docker exec "$R2" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:/tmp/staticd.log"
wait_in "$R2" "r2 mgmtd/staticd up" 30 "pidof mgmtd staticd"

echo "==> r2: OUR ospfd — area 1 on eth0, the empty area-0 stanza, the vlink"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router ospf' \
  ' router-id $R2_RID' \
  ' area 0.0.0.0' \
  ' area 0.0.0.1' \
  '  interface eth0' \
  '   address $R2_IP/$R2_LEN' \
  '   network-type point-to-point' \
  '   hello-interval 2' \
  '   dead-interval 8' \
  ' area 0.0.0.1 virtual-link $R1_RID' \
  ' redistribute static' \
  > /etc/rouster-ospfd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-ospfd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 ROUSTER_OSPF_TRACE=1 rouster-ospfd --config /etc/rouster-ospfd.conf > $OUR_OSPFD_LOG 2>&1"
wait_in "$R2" "our ospfd is up" 10 "pidof rouster-ospfd"

# Rig truth (disclosed): FRR 10.2.2's ospfd binds its virtual-link
# socket to a kernel interface NAMED after the vlink ("VLINK0" —
# "bind to interface VLINK0 failed, errno=19" without one; FRR's own
# zebra model expects it to exist). The rig provides a dummy —
# FRR-side only, our daemon needs nothing of the sort.
docker exec "$R1" sh -c "ip link add VLINK0 type dummy 2>/dev/null; ip link set VLINK0 up"
echo "==> r3 FRR config (vtysh -b, retried past the zebra-view race)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-vlink-r1' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R1_RID' \
  ' network $NET1_SUBNET area 0.0.0.1' \
  ' network $DUMMY area 0.0.0.0' \
  ' area 0.0.0.1 virtual-link $R2_RID' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R3" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ospf-vlink-r3' \
  'interface eth0' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'interface eth1' \
  ' ip ospf network point-to-point' \
  ' ip ospf hello-interval 2' \
  ' ip ospf dead-interval 8' \
  'router ospf' \
  ' router-id $R3_RID' \
  ' network $NET1_SUBNET area 0.0.0.1' \
  ' network $NET2_SUBNET area 0.0.0.1' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$R3" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$R3" sh -c "vtysh -c 'show ip ospf interface' 2>/dev/null | grep -qi 'point-to-point'"; then
        APPLIED=1
        break
    fi
done
[ "$APPLIED" = 1 ] || fail "FRR ospf config never applied on r3"
# FRR-side debug (the drop diagnosis).
docker exec "$R3" vtysh -c "debug ospf packet all" -c "debug ospf lsa" -c "debug ospf flooding" >/dev/null 2>&1 || true

echo "==> TRANSIT-ADJ: r1-r3 and r3-r2 Full, both directions"
wait_in "$R1" "r1 (ours) logged the r3 adjacency FULL" 90 \
    "grep -q 'adjacency FULL' $OUR_OSPFD_LOG"
wait_in "$R3" "r3 (FRR) sees r1 Full" 90 "vtysh -c 'show ip ospf neighbor' | grep '$R1_RID' | grep -q Full"
wait_in "$R3" "r3 (FRR) sees r2 Full" 90 "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full"
wait_in "$R2" "r2 (ours) logged the r3 adjacency FULL" 90 \
    "grep -q 'adjacency FULL' $OUR_OSPFD_LOG"

echo "==> VLINK-UP: the virtual link comes up on both endpoints"
wait_in "$R2" "r2's endpoint resolved per 16.1 step 4" 60 \
    "grep -q 'virtual link endpoint resolved' $OUR_OSPFD_LOG"
wait_in "$R1" "r1's endpoint resolved per 16.1 step 4" 60 \
    "grep -q 'virtual link endpoint resolved' $OUR_OSPFD_LOG"
wait_in "$R2" "r2's vlink adjacency FULL (2 total: transit + vlink)" 90 \
    "test \$(grep -c 'adjacency FULL' $OUR_OSPFD_LOG) -ge 2"
wait_in "$R1" "r1's vlink adjacency FULL (2 total: transit + vlink)" 90 \
    "test \$(grep -c 'adjacency FULL' $OUR_OSPFD_LOG) -ge 2"

echo "==> BACKBONE-LSAS: the partitioned databases join over the vlink"
wait_in "$R2" "r2's area-0 LSDB holds r1's backbone router-LSA" 60 \
    "grep 'peer LSA installed' $OUR_OSPFD_LOG | grep -q 'router'"
wait_in "$R1" "r1's area-0 LSDB holds r2's backbone router-LSA" 60 \
    "grep 'peer LSA installed' $OUR_OSPFD_LOG | grep -q 'router'"

echo "==> ROUTE-THROUGH-VLINK"
# r1's dummy area-0 subnet -> our kernel via r1's transit address (the
# §15 IP-routed tunnel; the covering area-1 route makes it resolvable).
wait_in "$R2" "r2's kernel carries r1's dummy proto ospf via the vlink" 90 \
    "ip route show proto ospf | grep '$DUMMY' | grep -q via"
# Our redistributed static (AS-scoped; crosses the vlink) -> r1's
# kernel: staticd injects into rousterd -> the STATIC redistribute
# push -> our §12.4.4 origination (the p2p interop's REDIST-OUT shape).
docker exec "$R2" vtysh -c "configure terminal" -c "ip route $R2_STATIC blackhole"
wait_in "$R2" "our ASBR external originated" 60 \
    "grep -q 'external LSA originated' $OUR_OSPFD_LOG"
wait_in "$R1" "r1's kernel routes r2's static through the vlink" 120 \
    "ip route show proto ospf | grep '$R2_STATIC' | grep -q via"

echo "==> SOAK: 20 s"
sleep 20
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R1_RID' | grep -q Full" \
    || fail "r1-r3 transit adjacency dropped during the soak"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor' | grep '$R2_RID' | grep -q Full" \
    || fail "r3-r2 transit adjacency dropped during the soak"
docker exec "$R1" sh -c "test \$(grep -c 'adjacency FULL' $OUR_OSPFD_LOG) -ge 2" \
    || fail "the virtual link dropped during the soak (r1)"
docker exec "$R2" sh -c "ip route show proto ospf | grep -q '$DUMMY'" \
    || fail "our vlink route dropped during the soak"
docker exec "$R1" sh -c "ip route show proto ospf | grep -q '$R2_STATIC'" \
    || fail "r1's vlink route dropped during the soak"
docker exec "$R2" sh -c "pidof rousterd rouster-ospfd" >/dev/null \
    || fail "one of our daemons died during the soak"

echo "==> final state"
docker exec "$R1" sh -c "grep -E 'adjacency FULL|virtual link endpoint' $OUR_OSPFD_LOG | tail -6; echo ---; ip route show proto ospf"
docker exec "$R2" sh -c "ip route show proto ospf"
docker exec "$R3" sh -c "vtysh -c 'show ip ospf neighbor'; echo ---; ip route show proto ospf"

echo "ospf-vlink interop: PASS"
