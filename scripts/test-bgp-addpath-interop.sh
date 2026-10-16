#!/usr/bin/env bash
# BGP ADD-PATH receive interop (N5B, RFC 7911): a real FRR 10.2.2 hub
# sending multiple paths, our bgpd receiving them.
#
#   bgp-ap-us  (ours):  rousterd (zebra) + rouster bgpd, AS 65000,
#                       `neighbor HUB addpath rx` + passive
#   bgp-ap-hub (FRR):   AS 65010, two leaf peers,
#                       `neighbor US addpath-tx-best-selected 2`
#   bgp-ap-l1  (FRR):   AS 65001, network 203.0.113.0/24
#   bgp-ap-l2  (FRR):   AS 65002, network 203.0.113.0/24
#
# Machine checks (script exit 0):
#   - ESTABLISHED: the hub session Established on both sides, the two
#     leaf sessions Established on the hub.
#   - HUB-TWO-PATHS: the hub's own table holds both leafs' paths for
#     the prefix (the precondition for sending two).
#   - ADDPATH-PATHS-RECEIVED: our bgpd logged the prefix arriving
#     under two DISTINCT ADD-PATH path identifiers ("path <n>
#     203.0.113.0/24" in the UPDATE-received lines — the extended
#     NLRI decoded, RFC 7911 §3).
#   - SESSION-CLEAN: no NOTIFICATION either direction, no malformed
#     message (the /0 hazard would have poisoned the NLRI decode).
#   - SINGLE-BEST-KERNEL: exactly ONE proto bgp route for the prefix
#     in our kernel — the Loc-RIB still elects a single best per
#     prefix regardless of sibling count (RFC 7911 §5: procedures
#     otherwise unchanged).
#
# Never pulls images (frr-testbed:10.2.2 cached); self-cleaning;
# quarantine under away/2026-10-11/night/quarantine/bgp-addpath/ on
# success AND failure.
#
#   scripts/test-bgp-addpath-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

US=bgp-ap-us
HUB=bgp-ap-hub
L1=bgp-ap-l1
L2=bgp-ap-l2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/tmp/bgpd.log
OUR_BGPD_LOG=/var/log/rouster-bgpd.log
PREFIX=203.0.113.0/24
QUARANTINE="${ROUSTER_BGP_ADDPATH_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/bgp-addpath}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/us" "$QUARANTINE/hub" "$QUARANTINE/l1" "$QUARANTINE/l2"
    docker cp "$US:$OUR_BGPD_LOG" "$QUARANTINE/us/rouster-bgpd.log" 2>/dev/null || true
    docker cp "$US:$ROUSTERD_LOG" "$QUARANTINE/us/rousterd.log" 2>/dev/null || true
    docker exec "$US" sh -c "cat /etc/rouster-bgp.conf; echo ---; ip route show; echo --- proto bgp:; ip route show proto bgp" \
        > "$QUARANTINE/us/state.txt" 2>&1 || true
    for side in hub l1 l2; do
        name="$HUB"; [ "$side" = l1 ] && name="$L1"; [ "$side" = l2 ] && name="$L2"
        docker exec "$name" sh -c "vtysh -c 'show bgp summary'; echo ---; vtysh -c 'show bgp ipv4 unicast'; echo ---; vtysh -c 'show bgp ipv4 unicast json'" \
            > "$QUARANTINE/$side/bgp.txt" 2>&1 || true
        docker cp "$name:$BGPD_LOG" "$QUARANTINE/$side/frr-bgpd.log" 2>/dev/null || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- our bgpd tail ---" >&2
    docker exec "$US" sh -c "tail -40 $OUR_BGPD_LOG" >&2 || true
    echo "--- our bgpd addpath-relevant lines ---" >&2
    docker exec "$US" sh -c "grep -E 'UPDATE received|NOTIFICATION|malformed|Established' $OUR_BGPD_LOG" >&2 || true
    echo "--- hub bgpd tail ---" >&2
    docker exec "$HUB" sh -c "tail -25 $BGPD_LOG" >&2 || true
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

trap 'capture; docker rm -f "$US" "$HUB" "$L1" "$L2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$US" "$HUB" "$L1" "$L2" >/dev/null 2>&1 || true

echo "==> building rousterd + bgpd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bgpd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$US" "$HUB" "$L1" "$L2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$name" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos"
done
for name in "$US" "$HUB" "$L1" "$L2"; do
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
done
docker cp "target/$MUSL_TARGET/release/bgpd" "$US:/usr/local/bin/rouster-bgpd"

US_IP=$(bridge_ip "$US")
HUB_IP=$(bridge_ip "$HUB")
L1_IP=$(bridge_ip "$L1")
L2_IP=$(bridge_ip "$L2")
echo "==> bridge addresses: us=$US_IP hub=$HUB_IP l1=$L1_IP l2=$L2_IP"

# The leafs: one prefix from two ASes (the hub's two paths).
for side in l1 l2; do
    name="$L1"; asn=65001; [ "$side" = l2 ] && { name="$L2"; asn=65002; }
    echo "==> $side: resident rousterd (zebra) + mgmtd + REAL FRR bgpd (AS $asn, network $PREFIX)"
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d -e ROUSTERD_LOG=debug "$name" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
    wait_in "$name" "$side rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
    docker exec "$name" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
    docker exec "$name" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
    wait_in "$name" "$side bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"
    docker exec "$name" sh -c "printf '%s\n' \
      'frr version 10.2' \
      'frr defaults traditional' \
      'hostname ap-$side' \
      'router bgp $asn' \
      ' no bgp ebgp-requires-policy' \
      ' no bgp network import-check' \
      ' neighbor $HUB_IP remote-as 65010' \
      ' neighbor $HUB_IP timers 10 30' \
      ' address-family ipv4 unicast' \
      '  network $PREFIX' \
      ' exit-address-family' \
      ' exit' \
      'line vty' \
      > $FRR_CONF"
    APPLIED=0
    for _ in $(seq 1 10); do
        docker exec "$name" vtysh -b >/dev/null 2>&1 || true
        sleep 2
        if docker exec "$name" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$HUB_IP'"; then
            APPLIED=1; break
        fi
    done
    [ "$APPLIED" = 1 ] || fail "$side config never applied"
done

echo "==> hub: resident rousterd (zebra) + mgmtd + REAL FRR bgpd (AS 65010, config applied AFTER our listener is up — FRR's connect retry is 120 s, the first attempt must not hit a closed port)"
docker exec "$HUB" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d -e ROUSTERD_LOG=debug "$HUB" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$HUB" "hub rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
docker exec "$HUB" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
docker exec "$HUB" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$HUB" "hub bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"

echo "==> us: resident rousterd (zebra) + rouster bgpd (AS 65000, addpath rx, passive)"
docker exec "$US" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d -e ROUSTERD_LOG=debug "$US" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$US" "us rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
docker exec "$US" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router bgp 65000' \
  ' bgp router-id $US_IP' \
  ' hold-time 30' \
  ' neighbor $HUB_IP remote-as 65010' \
  ' neighbor $HUB_IP passive' \
  ' neighbor $HUB_IP addpath rx' \
  > /etc/rouster-bgp.conf"
docker exec "$US" sh -c "cat /etc/rouster-bgp.conf"

docker exec "$HUB" ping -c1 -W1 "$US_IP" >/dev/null 2>&1 || true
docker exec "$US" ping -c1 -W1 "$HUB_IP" >/dev/null 2>&1 || true

echo "==> starting our bgpd"
docker exec -d "$US" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > $OUR_BGPD_LOG 2>&1"
wait_in "$US" "our bgpd up" 10 "pidof rouster-bgpd"
wait_in "$US" "our bgpd listening" 10 "grep -q 'bgpd: listening' $OUR_BGPD_LOG"

echo "==> hub config (dials us now that the listener is up)"
docker exec "$HUB" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname ap-hub' \
  'router bgp 65010' \
  ' no bgp ebgp-requires-policy' \
  ' neighbor $L1_IP remote-as 65001' \
  ' neighbor $L1_IP timers 10 30' \
  ' neighbor $L2_IP remote-as 65002' \
  ' neighbor $L2_IP timers 10 30' \
  ' neighbor $US_IP remote-as 65000' \
  ' neighbor $US_IP timers 10 30' \
  ' address-family ipv4 unicast' \
  '  neighbor $US_IP addpath-tx-best-selected 2' \
  ' exit-address-family' \
  ' exit' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$HUB" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$HUB" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$US_IP'"; then
        APPLIED=1; break
    fi
done
[ "$APPLIED" = 1 ] || fail "hub config never applied"

echo "==> ESTABLISHED: hub<->us and both leaf sessions"
# 150 s: one full FRR ConnectRetry cycle (120 s default) still fits.
wait_in "$HUB" "hub Established with us" 150 \
    "vtysh -c 'show bgp neighbor $US_IP' | grep -q 'BGP state = Established'"
wait_in "$HUB" "hub Established with l1" 150 \
    "vtysh -c 'show bgp neighbor $L1_IP' | grep -q 'BGP state = Established'"
wait_in "$HUB" "hub Established with l2" 150 \
    "vtysh -c 'show bgp neighbor $L2_IP' | grep -q 'BGP state = Established'"
wait_in "$US" "our bgpd logged the hub Established" 60 \
    "grep 'session Established' $OUR_BGPD_LOG | grep -q '$HUB_IP'"

echo "==> HUB-TWO-PATHS: the hub table holds both leafs' paths"
wait_in "$HUB" "hub has two paths for $PREFIX" 30 \
    "vtysh -c 'show bgp ipv4 unicast $PREFIX' | grep -c '^  65' | grep -q 2"
HUB_JSON=$(docker exec "$HUB" vtysh -c 'show bgp ipv4 unicast json')
echo "$HUB_JSON" | grep -q '"path":"65001"' \
    || fail "hub lacks the 65001 path: $(echo "$HUB_JSON" | grep -o '"path":"[^"]*"')"
echo "$HUB_JSON" | grep -q '"path":"65002"' \
    || fail "hub lacks the 65002 path: $(echo "$HUB_JSON" | grep -o '"path":"[^"]*"')"

echo "==> ADDPATH-PATHS-RECEIVED: two distinct path ids for $PREFIX in our log"
wait_in "$US" "our bgpd received the prefix under a path id" 30 \
    "grep 'UPDATE received' $OUR_BGPD_LOG | grep -qE 'path [0-9]+ $PREFIX'"
PATHS=$(docker exec "$US" sh -c "grep 'UPDATE received' $OUR_BGPD_LOG | grep -oE 'path [0-9]+ $PREFIX' | sort -u")
echo "$PATHS"
[ "$(echo "$PATHS" | wc -l | tr -d ' ')" = 2 ] \
    || fail "expected 2 distinct path ids, got: $PATHS"

echo "==> SESSION-CLEAN: no NOTIFICATION, no malformed decode"
sleep 3
docker exec "$US" sh -c "grep -q 'NOTIFICATION' $OUR_BGPD_LOG" \
    && fail "a NOTIFICATION crossed the session"
docker exec "$US" sh -c "grep -q 'malformed message' $OUR_BGPD_LOG" \
    && fail "a malformed message hit the decoder (the /0 hazard would land here)"
docker exec "$HUB" sh -c "vtysh -c 'show bgp neighbor $US_IP' | grep -q 'BGP state = Established'" \
    || fail "the session dropped after the addpath exchange"

echo "==> SINGLE-BEST-KERNEL: exactly one proto bgp route for $PREFIX"
wait_in "$US" "rousterd programmed the best route" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$PREFIX'"
ROUTES=$(docker exec "$US" sh -c "ip route show proto bgp | grep -c '$PREFIX' || true")
echo "proto bgp routes for $PREFIX: $ROUTES"
[ "$ROUTES" = 1 ] \
    || { docker exec "$US" ip route show proto bgp; fail "expected exactly 1 best route, got $ROUTES"; }

echo "==> final state"
docker exec "$US" sh -c "ip route show proto bgp; echo '(us kernel: the single best)'"
docker exec "$HUB" sh -c "vtysh -c 'show bgp ipv4 unicast'"

echo "bgp-addpath interop: PASS"
