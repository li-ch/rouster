#!/usr/bin/env bash
# Z5C interop (direction A, ospfd — W1B): TWO real FRR 10.2.2 ospfd
# instances form a FULL OSPF adjacency (area 0) while BOTH use rousterd as
# their zebra over ZAPI; the OSPF-learned route to the OTHER router's
# loopback must land in the Linux kernel through rousterd.
#
#   z5c-r1: ospfd + mgmtd --z--> rousterd #1 --netlink--> kernel #1
#     OSPF area 0 over the docker bridge eth0 pair (multicast 224.0.0.5)
#   z5c-r2: ospfd + mgmtd --z--> rousterd #2 --netlink--> kernel #2
#
# Topology: the pre-registered loopback pair — each container's lo carries
# a distinct /32 (10.255.1.1, 10.255.2.1) BEFORE rousterd starts so the
# initial mirror carries it; `network` statements enable OSPF on the
# bridge subnet (adjacency transit) and on the loopback /32s (advertised
# stub networks). Two containers on the docker default bridge, same shape
# as Z5B: one shared kernel would mirror both peers' addresses to both
# ospfds and break the mirror-disjointness every protocol daemon expects.
#
# Router IDs are NOT pinned in config: ospfd's ROUTER_ID_ADD (16) is
# answered by rousterd's derived ROUTER_ID_UPDATE (18) — highest non-127/8
# loopback address, so each side derives its own loopback /32 as router-id
# (10.255.1.1 / 10.255.2.1). This is the first live validation of that
# answer (W2 landed the message; W1B closed the 127/8 exclusion).
#
# Flow:
#   1. rousterd resident in both containers (lo /32s configured BEFORE
#      startup so the initial mirror + router-id derivation carry them).
#   2. mgmtd + real ospfd start against rousterd (`-d -z`).
#   3. `vtysh -b` pushes the OSPF configs (no daemon-specific config
#      auto-read in this build — Z1 deviation 1; mgmtd-backed push only).
#   4. DR/BDR election over the bridge, LSDB sync, SPF; each ospfd sends
#      ROUTE_ADD (type=OSPF=7) for the REMOTE loopback /32 to ITS
#      rousterd -> kernel `proto ospf` (RTPROT_OSPF 188).
#
# Machine checks (script exit 0):
#   - ATTACH: each rousterd logged `zapi: session established` with
#     protocol=7 (ospfd's single zclient), /var/run/frr/ospfd.vty exists,
#     and the session count NEVER grows (no reconnect loop).
#   - ADJACENCY (precondition for the route): `show ip ospf neighbor`
#     reports a Full neighbor on BOTH sides.
#   - ROUTE-KERNEL: r1's kernel shows 10.255.2.1/32 `proto ospf` AND r1's
#     rousterd logged `zapi: route add` for that prefix (installed by
#     rousterd, not by anyone else); symmetric on r2 for 10.255.1.1/32.
#   - STABLE (soak): 60 s after installation both neighbors still Full,
#     both routes still present, the zapi socket exists, every daemon
#     alive, and neither rousterd saw a session reconnect.
#
# `echo '188 ospf' >> /etc/iproute2/rt_protos` gives the kernel's
# RTPROT_OSPF (188) its name inside the container — the mapping a real FRR
# install ships; without it `ip route show proto ospf` cannot match.
#
# Never pulls images. Container caps as Z5/Z5B (NET_ADMIN/NET_RAW/
# SYS_ADMIN — mgmtd's privs_init demand; still non-privileged). The
# host's network is never touched: containers use the docker default
# bridge, the transit subnet is read from the running containers, and the
# trap removes both. rousterd runs with NO_COLOR=1 so quarantine logs are
# ANSI-free even on older binaries (the in-daemon TTY detection is W3's).
# Logs are copied to the quarantine dir on success AND failure (trap).
#
#   scripts/test-z5c-ospfd-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=z5c-r1
R2=z5c-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OSPFD_LOG=/tmp/ospfd.log
MGMTD_LOG=/tmp/mgmtd.log
R1_LO=10.255.1.1/32        # r1's advertised loopback, r2 must learn it
R2_LO=10.255.2.1/32        # r2's advertised loopback, r1 must learn it
# away/<program>/quarantine/z5c sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_Z5C_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/z5c}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# The bridge subnet of a container's eth0 (kernel connected route form):
# `192.168.215.0/24 proto kernel scope link src ...`.
bridge_subnet() {
    docker exec "$1" sh -c "ip -4 route show dev eth0 proto kernel" | awk '{print $1; exit}'
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="z5c-$side"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker cp "$name:$OSPFD_LOG" "$QUARANTINE/$side/ospfd.log" 2>/dev/null || true
        docker cp "$name:$MGMTD_LOG" "$QUARANTINE/$side/mgmtd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto ospf; echo ---; ip addr show lo" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show ip ospf'; echo ---; vtysh -c 'show ip ospf neighbor'; echo ---; vtysh -c 'show ip ospf database'" \
            > "$QUARANTINE/$side/ospf.txt" 2>&1 || true
        docker exec "$name" sh -c "ls -l $ZAPI_SOCK; pidof rousterd ospfd mgmtd" \
            > "$QUARANTINE/$side/env.txt" 2>&1 || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    for side in r1 r2; do
        echo "--- $side rousterd tail ---" >&2
        docker exec "z5c-$side" sh -c "tail -30 $ROUSTERD_LOG" >&2 || true
        echo "--- $side ospfd tail ---" >&2
        docker exec "z5c-$side" sh -c "tail -15 $OSPFD_LOG" >&2 || true
        echo "--- $side ospf neighbor ---" >&2
        docker exec "z5c-$side" sh -c "vtysh -c 'show ip ospf neighbor'" >&2 || true
    done
    return 1
}

wait_in() {
    local side="$1" desc="$2" attempts="$3" body="$4"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "z5c-$side" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    fail "$desc (waited ${attempts}s, side $side)"
}

trap 'capture; docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true

echo "==> building rousterd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd

echo "==> starting containers $R1 and $R2 from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
done

# Loopback pair BEFORE rousterd starts: the initial interface mirror and
# the router-id derivation must already carry them.
docker exec "$R1" sh -c "ip addr add $R1_LO dev lo"
docker exec "$R2" sh -c "ip addr add $R2_LO dev lo"

echo "==> resident rousterd in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "echo '188 ospf' >> /etc/iproute2/rt_protos"
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d -e ROUSTERD_LOG=debug "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in r1 "rousterd r1 listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in r2 "rousterd r2 listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in r1 "r1 zapi socket" 10 "test -S $ZAPI_SOCK"
wait_in r2 "r2 zapi socket" 10 "test -S $ZAPI_SOCK"

SUBNET=$(bridge_subnet "$R1")
echo "==> bridge transit subnet: $SUBNET"

echo "==> starting mgmtd and REAL FRR ospfd against rousterd"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c \
        "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
    docker exec "$name" sh -c \
        "/usr/lib/frr/ospfd -d -z $ZAPI_SOCK --log file:$OSPFD_LOG --log-level debug"
done
wait_in r1 "r1 daemons up" 20 "pidof mgmtd ospfd"
wait_in r2 "r2 daemons up" 20 "pidof mgmtd ospfd"
wait_in r1 "r1 ospfd vty socket" 30 "test -S /var/run/frr/ospfd.vty"
wait_in r2 "r2 ospfd vty socket" 30 "test -S /var/run/frr/ospfd.vty"

echo "==> ATTACH: ospfd sessions established against both rousterds (protocol=7)"
wait_in r1 "r1 ospfd attached" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
wait_in r2 "r2 ospfd attached" 30 "grep -q 'session established.*protocol=7' $ROUSTERD_LOG"
R1_SESSIONS=$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG")
R2_SESSIONS=$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG")

echo "==> OSPF config push (network statements: transit + loopback /32s)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r1' \
  'router ospf' \
  ' network $SUBNET area 0.0.0.0' \
  ' network $R1_LO area 0.0.0.0' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R2" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r2' \
  'router ospf' \
  ' network $SUBNET area 0.0.0.0' \
  ' network $R2_LO area 0.0.0.0' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R1" vtysh -b
docker exec "$R2" vtysh -b

echo "==> waiting for FULL adjacency (DR/BDR election + LSDB sync)"
# ospfd's router-id comes from rousterd's ROUTER_ID_UPDATE answer; assert
# each side derived its OWN loopback (the 127/8 exclusion at work).
wait_in r1 "r1 router-id derived from its loopback" 30 \
    "vtysh -c 'show ip ospf' | grep -q 'Router ID: 10.255.1.1'"
wait_in r2 "r2 router-id derived from its loopback" 30 \
    "vtysh -c 'show ip ospf' | grep -q 'Router ID: 10.255.2.1'"
wait_in r1 "r1 neighbor Full" 120 "vtysh -c 'show ip ospf neighbor' | grep -q Full"
wait_in r2 "r2 neighbor Full" 120 "vtysh -c 'show ip ospf neighbor' | grep -q Full"

echo "==> waiting for the OSPF-learned loopbacks to reach BOTH kernels THROUGH rousterd"
R1_LO_ADDR=${R1_LO%/*}
R2_LO_ADDR=${R2_LO%/*}
wait_in r1 "rousterd r1 logged the OSPF route add for $R2_LO" 60 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$R2_LO_ADDR/32' "
wait_in r2 "rousterd r2 logged the OSPF route add for $R1_LO" 60 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$R1_LO_ADDR/32' "
wait_in r1 "$R2_LO in r1 kernel proto ospf" 30 \
    "ip route show proto ospf | grep -q '$R2_LO_ADDR'"
wait_in r2 "$R1_LO in r2 kernel proto ospf" 30 \
    "ip route show proto ospf | grep -q '$R1_LO_ADDR'"
docker exec "$R1" sh -c "ip route show $R2_LO_ADDR"
docker exec "$R2" sh -c "ip route show $R1_LO_ADDR"

echo "==> STABLE: 60 s soak after route installation"
sleep 62
wait_in r1 "r1 neighbor still Full" 10 "vtysh -c 'show ip ospf neighbor' | grep -q Full"
wait_in r2 "r2 neighbor still Full" 10 "vtysh -c 'show ip ospf neighbor' | grep -q Full"
wait_in r1 "r1 daemons alive" 10 "pidof rousterd ospfd mgmtd"
wait_in r2 "r2 daemons alive" 10 "pidof rousterd ospfd mgmtd"
[ "$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG")" = "$R1_SESSIONS" ] \
    || fail "r1 saw a zapi reconnect during the soak ($R1_SESSIONS -> now)"
[ "$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG")" = "$R2_SESSIONS" ] \
    || fail "r2 saw a zapi reconnect during the soak ($R2_SESSIONS -> now)"
wait_in r1 "r1 zapi socket alive" 10 "test -S $ZAPI_SOCK"
wait_in r2 "r2 zapi socket alive" 10 "test -S $ZAPI_SOCK"
wait_in r1 "r1 still holds the OSPF-learned loopback" 10 \
    "ip route show proto ospf | grep -q '$R2_LO_ADDR'"
wait_in r2 "r2 still holds the OSPF-learned loopback" 10 \
    "ip route show proto ospf | grep -q '$R1_LO_ADDR'"

echo "==> final state"
docker exec "$R1" sh -c "echo '--- r1 ospf routes ---'; ip route show proto ospf"
docker exec "$R2" sh -c "echo '--- r2 ospf routes ---'; ip route show proto ospf"
docker exec "$R1" vtysh -c 'show ip ospf neighbor'
docker exec "$R2" vtysh -c 'show ip ospf neighbor'

echo "z5c ospfd interop: PASS"
