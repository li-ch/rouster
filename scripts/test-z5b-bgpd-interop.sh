#!/usr/bin/env bash
# Z5B interop (direction A, bgpd): TWO real FRR 10.2.2 bgpd instances peer
# iBGP (AS 65000) while BOTH use rousterd as their zebra over ZAPI; a
# BGP-learned route must land in the Linux kernel through rousterd. This is
# the implementation-plan Phase-1 credibility milestone.
#
#   z5b-r1: bgpd + staticd + mgmtd --z--> rousterd #1 --netlink--> kernel #1
#     iBGP AS 65000 over the docker bridge eth0 pair
#   z5b-r2: bgpd + mgmtd         --z--> rousterd #2 --netlink--> kernel #2
#
# Shape deviation from the pre-registered one-container recipe (-N other
# pathspace), discovered empirically: bgpd REFUSES a neighbor whose address
# appears in its own zebra-mirrored connected prefixes ("Can not configure
# the local system as neighbor" — it consults the interface state rousterd
# mirrors). One shared kernel means both peers' addresses are local to both
# bgpds, so the iBGP session cannot form in a single netns. Two containers
# on the docker default bridge restore disjoint mirrored views (and are the
# realistic deployment shape); every other mechanic follows the Z5 script:
# musl rousterd -> docker cp -> mgmtd-backed `vtysh -b` config push
# (no daemon-specific config auto-read in this build, Z1 deviation 1).
#
# Flow:
#   1. rousterd resident in both containers (dummy-free topology: the
#      bridge eth0 IS the transit; each rousterd's initial mirror carries
#      its own eth0, so bgpd NHT for the peer's eth0 address resolves).
#   2. mgmtd (+staticd on r1) and real bgpd start against rousterd.
#   3. ONE `vtysh -b` pushes the full iBGP configs: r1 announces `network
#      203.0.113.0/24` (no import-check) and holds `ip route
#      198.51.100.0/24 blackhole`; r2 receives both and installs them into
#      ITS rousterd -> kernel `proto bgp`.
#   4. Redistribution channel live (Z5B hazard) with no ordering
#      constraint: whether r1's `redistribute static` registration lands
#      before staticd's route or after it, bgpd receives 198.51.100.0/24
#      from rousterd — the live best-change push (registration first) or
#      the initial dump at registration (route first, W2 commit 58b0dbe)
#      — accepts it, advertises it iBGP, and r2 installs the second
#      BGP-learned prefix too. (W1 needed a two-phase push — the route in
#      a second `vtysh -b` — precisely because the dump did not exist.)
#
# Machine checks (script exit 0):
#   - PEER: `show bgp neighbor` reports "BGP state = Established" on BOTH
#     bgpds (each through its own vtysh).
#   - ROUTE-KERNEL: r2's kernel shows 203.0.113.0/24 `proto bgp` AND r2's
#     rousterd logged `zapi: route add` for that prefix (installed by
#     rousterd, not by anyone else).
#   - REDISTRIBUTE: 198.51.100.0/24 reaches r2's kernel `proto bgp` after
#     r1's rousterd logged a redistribute push — the live
#     `pushing REDISTRIBUTE_ROUTE_ADD` or the `initial redistribute dump
#     push` (whichever ordering a run exercises).
#   - STABLE: 60 s after installation the session is still Established on
#     both sides, both routes still present, the zapi socket file exists,
#     every daemon alive, and neither rousterd saw a single session
#     reconnect (session-established count unchanged) — Z1's "bgpd
#     deadlocks against a silent zebra" hazard disproven in practice.
#
# `echo 186 bgp >> /etc/iproute2/rt_protos` gives the kernel's RTPROT_BGP
# (186) its name inside the container — the mapping a real FRR install
# ships; without it `ip route show proto bgp` cannot match.
#
# Never pulls images. Container caps as Z5 (NET_ADMIN/NET_RAW/SYS_ADMIN —
# mgmtd's privs_init demand; still non-privileged). The host's network is
# never touched: containers use the docker default bridge, peer IPs are
# read from the running containers, and the trap removes both. rousterd
# colorizes only on a TTY, so the redirected log files (and their
# quarantine copies) are ANSI-free with no env workaround. Logs are
# copied to the quarantine dir on success AND failure (trap).
#
#   scripts/test-z5b-bgpd-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=z5b-r1
R2=z5b-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/tmp/bgpd.log
STATICD_LOG=/tmp/staticd.log
MGMTD_LOG=/tmp/mgmtd.log
ANNOUNCED=203.0.113.0/24      # bgpd1-originated, learned via iBGP on r2
REDIS_PREFIX=198.51.100.0/24  # staticd -> REDISTRIBUTE push -> iBGP on r2
# away/<program>/quarantine/z5b sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_Z5B_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-09/quarantine/z5b}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# IPv4 address of eth0 inside a container (docker default bridge).
bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="z5b-$side"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker cp "$name:$BGPD_LOG" "$QUARANTINE/$side/bgpd.log" 2>/dev/null || true
        docker cp "$name:$MGMTD_LOG" "$QUARANTINE/$side/mgmtd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto bgp; echo ---; ip route show proto static" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show bgp summary'; echo ---; vtysh -c 'show bgp neighbor'" \
            > "$QUARANTINE/$side/bgp.txt" 2>&1 || true
        docker exec "$name" sh -c "ls -l $ZAPI_SOCK; pidof rousterd bgpd mgmtd staticd" \
            > "$QUARANTINE/$side/env.txt" 2>&1 || true
    done
    docker cp "$R1:$STATICD_LOG" "$QUARANTINE/r1/staticd.log" 2>/dev/null || true
}

fail() {
    echo "FAIL: $*" >&2
    for side in r1 r2; do
        echo "--- $side rousterd tail ---" >&2
        docker exec "z5b-$side" sh -c "tail -30 $ROUSTERD_LOG" >&2 || true
        echo "--- $side bgpd tail ---" >&2
        docker exec "z5b-$side" sh -c "tail -15 $BGPD_LOG" >&2 || true
    done
    return 1
}

wait_in() {
    local side="$1" desc="$2" attempts="$3" body="$4"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "z5b-$side" sh -c "$body" >/dev/null 2>&1; then
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

R1_IP=$(bridge_ip "$R1")
R2_IP=$(bridge_ip "$R2")
echo "==> bridge addresses: r1=$R1_IP r2=$R2_IP"

echo "==> resident rousterd in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos"
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in r1 "rousterd r1 listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in r2 "rousterd r2 listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in r1 "r1 zapi socket" 10 "test -S $ZAPI_SOCK"
wait_in r2 "r2 zapi socket" 10 "test -S $ZAPI_SOCK"

echo "==> starting mgmtd (+staticd on r1) and REAL FRR bgpd against rousterd"
docker exec "$R1" sh -c \
    "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R1" sh -c \
    "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R1" sh -c \
    "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
docker exec "$R2" sh -c \
    "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R2" sh -c \
    "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in r1 "r1 daemons up" 20 "pidof mgmtd staticd bgpd"
wait_in r2 "r2 daemons up" 20 "pidof mgmtd bgpd"
wait_in r1 "r1 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"
wait_in r2 "r2 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"

echo "==> iBGP config push (single phase: dump or live push covers either"
echo "    registration-vs-route ordering)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r1' \
  'ip route $REDIS_PREFIX blackhole' \
  'router bgp 65000' \
  ' no bgp network import-check' \
  ' bgp router-id $R1_IP' \
  ' neighbor $R2_IP remote-as 65000' \
  ' address-family ipv4 unicast' \
  '  network $ANNOUNCED' \
  '  redistribute static' \
  ' exit-address-family' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R2" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r2' \
  'router bgp 65000' \
  ' bgp router-id $R2_IP' \
  ' neighbor $R1_IP remote-as 65000' \
  'line vty' \
  > $FRR_CONF"
docker exec "$R1" vtysh -b
docker exec "$R2" vtysh -b

echo "==> waiting for the iBGP session to establish (PEER)"
wait_in r1 "r1 sees session Established" 60 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'"
wait_in r2 "r2 sees session Established" 60 \
    "vtysh -c 'show bgp neighbor $R1_IP' | grep -q 'BGP state = Established'"

echo "==> waiting for the BGP-learned route to reach r2's kernel THROUGH rousterd"
wait_in r2 "rousterd r2 logged the BGP route add" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$ANNOUNCED'"
wait_in r2 "$ANNOUNCED in r2 kernel proto bgp" 30 \
    "ip route show proto bgp | grep -q '$ANNOUNCED'"
docker exec "$R2" sh -c "ip route show $ANNOUNCED"

echo "==> waiting for the redistribute channel: staticd -> rousterd push (dump or live) -> iBGP -> r2 kernel"
wait_in r1 "static route in r1 kernel (staticd via rousterd)" 30 \
    "ip route show proto static | grep -q '$REDIS_PREFIX'"
wait_in r1 "rousterd r1 pushed the redistribute route (dump or live)" 30 \
    "grep -Eq 'pushing REDISTRIBUTE_ROUTE_ADD|initial redistribute dump push' $ROUSTERD_LOG"
wait_in r2 "$REDIS_PREFIX in r2 kernel proto bgp" 30 \
    "ip route show proto bgp | grep -q '$REDIS_PREFIX'"

echo "==> STABLE: 60 s soak after route installation"
R1_SESSIONS=$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG")
R2_SESSIONS=$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG")
sleep 62
wait_in r1 "r1 session still Established" 10 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'"
wait_in r2 "r2 session still Established" 10 \
    "vtysh -c 'show bgp neighbor $R1_IP' | grep -q 'BGP state = Established'"
wait_in r1 "r1 daemons alive" 10 "pidof rousterd bgpd mgmtd staticd"
wait_in r2 "r2 daemons alive" 10 "pidof rousterd bgpd mgmtd"
[ "$(docker exec "$R1" sh -c "grep -c 'session established' $ROUSTERD_LOG")" = "$R1_SESSIONS" ] \
    || fail "r1 saw a zapi reconnect during the soak ($R1_SESSIONS -> now)"
[ "$(docker exec "$R2" sh -c "grep -c 'session established' $ROUSTERD_LOG")" = "$R2_SESSIONS" ] \
    || fail "r2 saw a zapi reconnect during the soak ($R2_SESSIONS -> now)"
wait_in r1 "r1 zapi socket alive" 10 "test -S $ZAPI_SOCK"
wait_in r2 "r2 zapi socket alive" 10 "test -S $ZAPI_SOCK"
wait_in r2 "both BGP routes still in r2 kernel" 10 \
    "ip route show proto bgp | grep -q '$ANNOUNCED' && ip route show proto bgp | grep -q '$REDIS_PREFIX'"

echo "==> final state"
docker exec "$R2" sh -c "echo '--- r2 bgp ---'; ip route show proto bgp"
docker exec "$R1" sh -c "echo '--- r1 static ---'; ip route show proto static"
docker exec "$R1" vtysh -c 'show bgp summary' | tail -4
docker exec "$R2" vtysh -c 'show bgp summary' | tail -4

echo "z5b bgpd interop: PASS"
