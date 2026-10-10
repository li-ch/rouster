#!/usr/bin/env bash
# BGP-FRR interop (P2-b, M5): Rouster's bgpd peers with the REAL FRR
# 10.2.2 bgpd, both directions over the docker bridge.
#
#   bgp-frr-r1 (FRR side):   rousterd (zebra) + mgmtd + REAL bgpd
#   bgp-rouster-r2 (ours):   rousterd (zebra) + rouster bgpd
#
#   eBGP AS 65001 (FRR, network 203.0.113.0/24) <-> AS 65000 (ours,
#   network 198.51.100.0/24), hold 30 / keepalive 10 both sides.
#
# Machine checks (script exit 0):
#   - PEER-BOTH: FRR `show bgp neighbor` reports Established AND our
#     bgpd logged "session Established".
#   - UPDATE-FRR->US: FRR's network prefix arrives: our bgpd logged
#     "UPDATE received" with 203.0.113.0/24.
#   - UPDATE-US->FRR: our network prefix lands in FRR's `show bgp ipv4
#     unicast` (198.51.100.0/24) — and NOT just kernel-side.
#   - KERNEL-EXPORT: our bgpd exported the learned route through
#     rousterd: r2's kernel shows 203.0.113.0/24 proto bgp AND r2's
#     rousterd logged "zapi: route add" for it.
#   - REFRESH-OUT: SIGUSR1 to our bgpd -> ROUTE-REFRESH to FRR ->
#     FRR re-advertises (a second UPDATE received logged after the
#     signal).
#   - REFRESH-IN: `clear bgp 65000 soft in` on r1 makes FRR ask US to
#     re-advertise: our bgpd logs "ROUTE-REFRESH received" and FRR's
#     show output still holds our prefix after the clear.
#   - SOAK: >= 40 s keepalive-driven stability (10 s keepalives, 30 s
#     hold): still Established both sides, zero NOTIFICATIONs in
#     either bgpd log.
#   - TEARDOWN: SIGTERM to our bgpd -> NOTIFICATION Cease observed on
#     the FRR side (bgpd.log "%NOTIFICATION: ... 6/2"), session down.
#
# Never pulls images (frr-testbed:10.2.2 cached); caps as the z5
# family (NET_ADMIN/NET_RAW/SYS_ADMIN; port 179 binds fine as
# container root); self-cleaning; quarantine (absolute path) under
# away/2026-10-11/quarantine/bgp/ on success AND failure.
#
#   scripts/test-bgp-frr-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=bgp-frr-r1
R2=bgp-rouster-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/tmp/bgpd.log         # FRR bgpd on r1
OUR_BGPD_LOG=/var/log/rouster-bgpd.log
FRR_NET=203.0.113.0/24         # FRR-originated
OUR_NET=198.51.100.0/24        # rouster-originated
QUARANTINE="${ROUSTER_BGP_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/quarantine/bgp}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="$R1"; [ "$side" = r2 ] && name="$R2"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto bgp" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
    done
    docker cp "$R1:$BGPD_LOG" "$QUARANTINE/r1/frr-bgpd.log" 2>/dev/null || true
    docker cp "$R1:$FRR_CONF" "$QUARANTINE/r1/frr.conf" 2>/dev/null || true
    docker exec "$R1" sh -c "vtysh -c 'show bgp summary'; echo ---; vtysh -c 'show bgp ipv4 unicast'; echo ---; vtysh -c 'show bgp neighbor'" \
        > "$QUARANTINE/r1/bgp.txt" 2>&1 || true
    docker cp "$R2:$OUR_BGPD_LOG" "$QUARANTINE/r2/rouster-bgpd.log" 2>/dev/null || true
    docker exec "$R2" sh -c "cat /etc/rouster-bgp.conf" \
        > "$QUARANTINE/r2/rouster-bgp.conf" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    for entry in "$R1:$ROUSTERD_LOG rousterd-r1" "$R2:$ROUSTERD_LOG rousterd-r2" "$R2:$OUR_BGPD_LOG our-bgpd"; do
        name="${entry%%:*}"; what="${entry#*:}"; log="${what%% *}"
        echo "--- $what tail ---" >&2
        docker exec "$name" sh -c "tail -25 $log" >&2 || true
    done
    echo "--- FRR bgpd tail ---" >&2
    docker exec "$R1" sh -c "tail -20 $BGPD_LOG" >&2 || true
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

echo "==> building rousterd + bgpd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bgpd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/bgpd" "$name:/usr/local/bin/rouster-bgpd"
    docker exec "$name" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos"
done

R1_IP=$(bridge_ip "$R1")
R2_IP=$(bridge_ip "$R2")
echo "==> bridge addresses: frr-r1=$R1_IP rouster-r2=$R2_IP"

echo "==> resident rousterd (zebra) in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in "$R1" "r1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$R2" "r2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> r1: mgmtd + REAL FRR bgpd against rousterd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$R1" "r1 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"
echo "==> r2: rouster bgpd against rousterd (TCP 179)"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router bgp 65000' \
  ' bgp router-id $R2_IP' \
  ' neighbor $R1_IP remote-as 65001' \
  ' hold-time 30' \
  ' network $OUR_NET' \
  > /etc/rouster-bgp.conf"
docker exec "$R2" sh -c "cat /etc/rouster-bgp.conf"

echo "==> FRR side config (vtysh -b)"
# All lines single-quoted inside the outer double-quoted sh -c (the
# z5b convention): the host expands $R2_IP/$FRR_NET/$FRR_CONF, the
# container's printf receives clean literals.
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname frr-r1' \
  'router bgp 65001' \
  ' no bgp network import-check' \
  ' no bgp ebgp-requires-policy' \
  ' neighbor $R2_IP remote-as 65000' \
  ' neighbor $R2_IP timers 10 30' \
  ' address-family ipv4 unicast' \
  '  network $FRR_NET' \
  ' exit-address-family' \
  'line vty' \
  > $FRR_CONF"

# bgpd's neighbor config only applies once its zebra view is up —
# a vtysh -b pushed too early makes bgpd silently drop the whole
# router-bgp stanza (no error, no neighbor, no :179 bind; disclosed —
# observed against rousterd @ 298d5a8, FRR 10.2.2). Retry the push
# until the neighbor actually exists.
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$R1" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$R1" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$R2_IP'"; then
        APPLIED=1
        break
    fi
done
[ "$APPLIED" = 1 ] || fail "FRR neighbor config never applied (zebra-view race)"
# FRR binds 179 once a BGP instance exists.
wait_in "$R1" "FRR bgpd bound :179" 20 "grep -qi '00B3' /proc/net/tcp"

echo "==> seeding both sides' ARP (the M3 NHT gate needs lladdr entries)"
docker exec "$R1" ping -c1 -W1 "$R2_IP" >/dev/null 2>&1 || true
docker exec "$R2" ping -c1 -W1 "$R1_IP" >/dev/null 2>&1 || true
docker exec "$R1" sh -c "ip neigh show $R2_IP dev eth0" | grep -q lladdr \
    || fail "r1 has no lladdr neighbour for $R2_IP"
docker exec "$R2" sh -c "ip neigh show $R1_IP dev eth0" | grep -q lladdr \
    || fail "r2 has no lladdr neighbour for $R1_IP"

echo "==> starting rouster bgpd on r2"
docker exec -d "$R2" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > $OUR_BGPD_LOG 2>&1"
wait_in "$R2" "our bgpd is up" 10 "pidof rouster-bgpd"

echo "==> PEER-BOTH: waiting for Established on both sides"
wait_in "$R1" "FRR sees Established" 60 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'"
wait_in "$R2" "our bgpd logged Established" 60 \
    "grep -q 'session Established' $OUR_BGPD_LOG"

echo "==> UPDATE-FRR->US: FRR's network prefix in our RIB-in"
wait_in "$R2" "our bgpd received $FRR_NET" 30 \
    "grep 'UPDATE received' $OUR_BGPD_LOG | grep -q '$FRR_NET'"

echo "==> UPDATE-US->FRR: our network prefix in FRR's RIB"
wait_in "$R1" "FRR has $OUR_NET in show bgp" 30 \
    "vtysh -c 'show bgp ipv4 unicast $OUR_NET' | grep -q '$OUR_NET'"

echo "==> KERNEL-EXPORT: learned route through rousterd into r2's kernel"
wait_in "$R2" "r2 rousterd logged the BGP route add" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$FRR_NET'"
wait_in "$R2" "$FRR_NET in r2 kernel proto bgp" 30 \
    "ip route show proto bgp | grep -q '$FRR_NET'"

echo "==> REFRESH-OUT: SIGUSR1 -> ROUTE-REFRESH -> FRR re-advertises"
BEFORE=$(docker exec "$R2" sh -c "grep -c 'UPDATE received' $OUR_BGPD_LOG" || echo 0)
docker exec "$R2" sh -c "kill -USR1 \$(pidof rouster-bgpd)"
sleep 3
AFTER=$(docker exec "$R2" sh -c "grep -c 'UPDATE received' $OUR_BGPD_LOG" || echo 0)
[ "$AFTER" -gt "$BEFORE" ] \
    || fail "refresh round-trip out: UPDATE count did not rise ($BEFORE -> $AFTER)"

echo "==> REFRESH-IN: FRR clear soft in -> FRR requests refresh from us"
docker exec "$R1" vtysh -c "clear bgp 65000 soft in"
sleep 3
wait_in "$R2" "our bgpd answered a refresh request" 15 \
    "grep -q 'ROUTE-REFRESH received' $OUR_BGPD_LOG"
wait_in "$R1" "FRR still holds $OUR_NET after soft clear" 15 \
    "vtysh -c 'show bgp ipv4 unicast $OUR_NET' | grep -q '$OUR_NET'"

echo "==> SOAK: 40 s keepalive-driven stability (10 s KA / 30 s hold)"
sleep 40
docker exec "$R1" sh -c "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'" \
    || fail "FRR session dropped during soak"
docker exec "$R2" sh -c "grep -q 'session Established' $OUR_BGPD_LOG" \
    || fail "our session dropped during soak"
[ "$(docker exec "$R1" sh -c "grep -c NOTIFICATION $BGPD_LOG || true")" = "0" ] \
    || fail "FRR bgpd logged NOTIFICATIONs during soak"
[ "$(docker exec "$R2" sh -c "grep -c 'NOTIFICATION received' $OUR_BGPD_LOG || true")" = "0" ] \
    || fail "our bgpd received NOTIFICATIONs during soak"
docker exec "$R2" sh -c "ip route show proto bgp | grep -q '$FRR_NET'" \
    || fail "kernel route lost during soak"

echo "==> TEARDOWN: SIGTERM our bgpd -> Cease on the FRR side"
docker exec "$R2" sh -c "kill -TERM \$(pidof rouster-bgpd)"
sleep 3
# FRR records the received Cease in `show bgp neighbor`'s Last reset
# line (bgpd.log does not carry it at this log config).
wait_in "$R1" "FRR observed the Cease NOTIFICATION" 20 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'Notification received (Cease/Administrative Shutdown)'"
wait_in "$R2" "our bgpd exited" 15 "! pidof rouster-bgpd"
docker exec "$R1" sh -c "! vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'" \
    || fail "FRR still Established after our Cease"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show bgp summary'" | tail -4
docker exec "$R2" sh -c "ip route show proto bgp; echo '(after teardown)'"

echo "bgp-frr interop: PASS"
