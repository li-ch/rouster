#!/usr/bin/env bash
# BGP route-server interop (N5 M2): FRR bgpd as route-server-client,
# our bgpd as the route server.
#
#   bgp-rs-rs (ours):  rousterd (zebra) + rouster bgpd, AS 65000,
#                      both neighbors `route-server` + passive
#   bgp-rs-c1 (FRR):   AS 65001, network 203.0.113.0/24, MED 77 out
#   bgp-rs-c2 (FRR):   AS 65002, receives the reflection
#
# Machine checks (script exit 0):
#   - ESTABLISHED-BOTH-CLIENTS: both FRR clients Established and our
#     bgpd logged both sessions Established.
#   - REFLECTED-TRANSPARENT (FRR doc/user/routeserver.rst:
#     `route-server-client` "enables the transparent mode ... some BGP
#     attributes (as-path, next-hop and MED) of the routes announced
#     to that peer are not modified"; B-10 overrides the MED leg —
#     RFC 4271 §5.1.4: "The MULTI_EXIT_DISC attribute received from a
#     neighboring AS MUST NOT be propagated to other neighboring
#     ASes", and LOCAL_PREF/OTC go with it per §5.1.5/RFC 9234):
#       * c2 holds 203.0.113.0/24,
#       * its AS path is exactly 65001 — the RS's 65000 never appears,
#       * the next hop is c1's address (not the RS's),
#       * MED 77 stripped (c1 sends it, the RS never forwards it).
#   - NO-CLIENT-TO-CLIENT-SESSION (S7-b): each client peers with the
#     RS ONLY — no direct session between the clients; the exchange
#     goes THROUGH the route server.
#   - EXCHANGE-BIDIRECTIONAL (S7-b): c2 announces 198.51.100.0/24 too;
#     c1 pulls it with `clear bgp ... soft in` (RFC 2918 — our RS
#     answers the refresh by re-advertising its Adj-RIB-Out) and the
#     reflection is transparent in THAT direction as well: c1's path
#     is exactly 65002, next hop c2's address, 65000 never appears,
#     and c1's own route never reflects back to it.
#   - RS-KERNEL-CLEAN: the RS itself installed nothing (route-server
#     RIB stays out of the kernel — no proto bgp route, no zapi route
#     add in rousterd's log) — for BOTH exchanged prefixes.
#
# FRR clients run `no bgp enforce-first-as` (the FRR docs' own note:
# "If you have a peering to RS (Route-Server), most likely you MUST
# disable the first AS enforcement") and `no bgp ebgp-requires-policy`
# (FRR 10.2's RFC 8212 default).
#
# Never pulls images (frr-testbed:10.2.2 cached); self-cleaning;
# quarantine under away/2026-10-11/night/quarantine/bgp-rs/ on success
# AND failure.
#
#   scripts/test-bgp-rs-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

RS=bgp-rs-rs
C1=bgp-rs-c1
C2=bgp-rs-c2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/tmp/bgpd.log
OUR_BGPD_LOG=/var/log/rouster-bgpd.log
REFLECTED=203.0.113.0/24
EXCHANGED=198.51.100.0/24
QUARANTINE="${ROUSTER_BGP_RS_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/bgp-rs}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/rs" "$QUARANTINE/c1" "$QUARANTINE/c2"
    docker cp "$RS:$OUR_BGPD_LOG" "$QUARANTINE/rs/rouster-bgpd.log" 2>/dev/null || true
    docker cp "$RS:$ROUSTERD_LOG" "$QUARANTINE/rs/rousterd.log" 2>/dev/null || true
    docker exec "$RS" sh -c "cat /etc/rouster-bgp.conf; echo ---; ip route show; echo ---; ip route show proto bgp" \
        > "$QUARANTINE/rs/state.txt" 2>&1 || true
    for side in c1 c2; do
        name="$C1"; [ "$side" = c2 ] && name="$C2"
        docker exec "$name" sh -c "vtysh -c 'show bgp summary'; echo ---; vtysh -c 'show bgp ipv4 unicast'; echo ---; vtysh -c 'show bgp ipv4 unicast json'" \
            > "$QUARANTINE/$side/bgp.txt" 2>&1 || true
        docker cp "$name:$BGPD_LOG" "$QUARANTINE/$side/frr-bgpd.log" 2>/dev/null || true
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
    done
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- our bgpd tail ---" >&2
    docker exec "$RS" sh -c "tail -25 $OUR_BGPD_LOG" >&2 || true
    echo "--- rousterd tail ---" >&2
    docker exec "$RS" sh -c "tail -25 $ROUSTERD_LOG" >&2 || true
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

trap 'capture; docker rm -f "$RS" "$C1" "$C2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$RS" "$C1" "$C2" >/dev/null 2>&1 || true

echo "==> building rousterd + bgpd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bgpd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$RS" "$C1" "$C2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker exec "$name" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos"
done
for name in "$RS" "$C1" "$C2"; do
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
done
docker cp "target/$MUSL_TARGET/release/bgpd" "$RS:/usr/local/bin/rouster-bgpd"

RS_IP=$(bridge_ip "$RS")
C1_IP=$(bridge_ip "$C1")
C2_IP=$(bridge_ip "$C2")
echo "==> bridge addresses: rs=$RS_IP c1=$C1_IP c2=$C2_IP"

echo "==> RS: resident rousterd (zebra)"
docker exec "$RS" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$RS" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$RS" "rs rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> RS: rouster bgpd as the route server (both clients route-server + passive)"
docker exec "$RS" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router bgp 65000' \
  ' bgp router-id $RS_IP' \
  ' hold-time 30' \
  ' neighbor $C1_IP remote-as 65001' \
  ' neighbor $C1_IP passive' \
  ' neighbor $C1_IP route-server' \
  ' neighbor $C2_IP remote-as 65002' \
  ' neighbor $C2_IP passive' \
  ' neighbor $C2_IP route-server' \
  > /etc/rouster-bgp.conf"
docker exec "$RS" sh -c "cat /etc/rouster-bgp.conf"

echo "==> c1: resident rousterd (zebra) + mgmtd + REAL FRR bgpd (AS 65001, MED 77 out)"
docker exec "$C1" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$C1" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$C1" "c1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
docker exec "$C1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
docker exec "$C1" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$C1" "c1 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"
docker exec "$C1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname rs-c1' \
  'router bgp 65001' \
  ' no bgp enforce-first-as' \
  ' no bgp ebgp-requires-policy' \
  ' no bgp network import-check' \
  ' neighbor $RS_IP remote-as 65000' \
  ' neighbor $RS_IP timers 10 30' \
  ' address-family ipv4 unicast' \
  '  network $REFLECTED' \
  '  neighbor $RS_IP route-map MEDOUT out' \
  ' exit-address-family' \
  ' exit' \
  'route-map MEDOUT permit 10' \
  ' set metric 77' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$C1" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$C1" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$RS_IP'"; then
        APPLIED=1; break
    fi
done
[ "$APPLIED" = 1 ] || fail "c1 config never applied"
wait_in "$C1" "c1 bgpd bound :179" 20 "grep -qi '00B3' /proc/net/tcp"
docker exec "$C1" ping -c1 -W1 "$RS_IP" >/dev/null 2>&1 || true
docker exec "$RS" ping -c1 -W1 "$C1_IP" >/dev/null 2>&1 || true

echo "==> starting the route server"
docker exec -d "$RS" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > $OUR_BGPD_LOG 2>&1"
wait_in "$RS" "route server up" 10 "pidof rouster-bgpd"

echo "==> ESTABLISHED-c1: client 1 first (its route must pre-date c2's dump)"
wait_in "$C1" "c1 Established" 60 \
    "vtysh -c 'show bgp neighbor $RS_IP' | grep -q 'BGP state = Established'"
wait_in "$RS" "our bgpd logged c1 Established" 60 \
    "grep 'session Established' $OUR_BGPD_LOG | grep -q '$C1_IP'"
wait_in "$RS" "our bgpd received the announced route" 30 \
    "grep 'UPDATE received' $OUR_BGPD_LOG | grep -q '$REFLECTED'"

echo "==> c2: second FRR client (AS 65002) — connects after c1 announced"
docker exec "$C2" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$C2" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$C2" "c2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
docker exec "$C2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
docker exec "$C2" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$C2" "c2 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"
docker exec "$C2" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname rs-c2' \
  'router bgp 65002' \
  ' no bgp enforce-first-as' \
  ' no bgp ebgp-requires-policy' \
  ' no bgp network import-check' \
  ' neighbor $RS_IP remote-as 65000' \
  ' neighbor $RS_IP timers 10 30' \
  ' address-family ipv4 unicast' \
  '  network $EXCHANGED' \
  ' exit-address-family' \
  ' exit' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$C2" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$C2" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$RS_IP'"; then
        APPLIED=1; break
    fi
done
[ "$APPLIED" = 1 ] || fail "c2 config never applied"
docker exec "$C2" ping -c1 -W1 "$RS_IP" >/dev/null 2>&1 || true

echo "==> ESTABLISHED-BOTH-CLIENTS"
wait_in "$C2" "c2 Established" 60 \
    "vtysh -c 'show bgp neighbor $RS_IP' | grep -q 'BGP state = Established'"
wait_in "$RS" "our bgpd logged c2 Established" 60 \
    "grep 'session Established' $OUR_BGPD_LOG | grep -q '$C2_IP'"

echo "==> NO-CLIENT-TO-CLIENT-SESSION: each client peers with the RS only"
for side in "$C1" "$C2"; do
    N=$(docker exec "$side" sh -c "vtysh -c 'show bgp ipv4 unicast summary json'" \
        | grep -o '"peerState"' | wc -l | tr -d ' ')
    [ "$N" = 1 ] \
        || fail "$side has $N peers (expected exactly the RS — no client-to-client session)"
done

echo "==> REFLECTED-TRANSPARENT: $REFLECTED on c2, path exactly 65001, NH $C1_IP, MED stripped (B-10)"
wait_in "$C2" "c2 holds the reflected route" 30 \
    "vtysh -c 'show bgp ipv4 unicast $REFLECTED' | grep -q 'BGP routing table entry for $REFLECTED'"
# The single-prefix detail view: the path line must be exactly 65001
# (indented, alone), next hop $C1_IP, NO metric 77 (B-10 strips the
# origin client's MED), best.
DETAIL=$(docker exec "$C2" sh -c "vtysh -c 'show bgp ipv4 unicast $REFLECTED'")
echo "$DETAIL" | grep -qE '^  65001$' \
    || fail "path is not exactly 65001: $(echo "$DETAIL" | sed -n '/^Paths:/,/^$/p' | head -8)"
echo "$DETAIL" | grep -qw 65000 \
    && fail "the route server's AS 65000 appears in the reflected route"
echo "$DETAIL" | grep -q "$C1_IP" \
    || fail "the origin client's next hop $C1_IP absent: $(echo "$DETAIL" | grep -A3 '65001')"
echo "$DETAIL" | grep -q 'metric 77' \
    && fail "MED 77 rode the reflection (B-10: RFC 4271 §5.1.4 strips it): $(echo "$DETAIL" | grep -i metric)"
echo "$DETAIL" | grep -q 'best (' \
    || fail "the reflected route is not the best path"
# JSON cross-check on the whole table.
ROUTE_JSON=$(docker exec "$C2" vtysh -c 'show bgp ipv4 unicast json')
echo "$ROUTE_JSON" | grep -q '"path":"65001"' \
    || fail "table json AS path is not exactly 65001: $(echo "$ROUTE_JSON" | grep -o '"path":"[^"]*"')"
echo "$ROUTE_JSON" | grep -q "\"ip\":\"$C1_IP\"" \
    || fail "table json next hop is not $C1_IP: $(echo "$ROUTE_JSON" | grep -o '"ip":"[^"]*"')"
echo "$ROUTE_JSON" | grep -q '"metric":77' \
    && fail "table json still carries MED 77 (B-10 strips it): $(echo "$ROUTE_JSON" | grep -o '"metric":[0-9]*' | sort -u)"

echo "==> EXCHANGE-BIDIRECTIONAL: c2's $EXCHANGED back to c1 (RFC 2918 soft-in pull)"
# c1 established before c2 existed, so its initial dump predates c2's
# route — c1 requests a re-advertisement (ROUTE-REFRESH, RFC 2918 §4)
# and our RS answers from its Adj-RIB-Out.
docker exec "$C1" vtysh -c "clear bgp ipv4 unicast $RS_IP soft in"
wait_in "$C1" "c1 holds the reverse-reflected route" 30 \
    "vtysh -c 'show bgp ipv4 unicast $EXCHANGED' | grep -q 'BGP routing table entry for $EXCHANGED'"
DETAIL_C1=$(docker exec "$C1" sh -c "vtysh -c 'show bgp ipv4 unicast $EXCHANGED'")
echo "$DETAIL_C1" | grep -qE '^  65002$' \
    || fail "reverse path is not exactly 65002: $(echo "$DETAIL_C1" | sed -n '/^Paths:/,/^$/p' | head -8)"
echo "$DETAIL_C1" | grep -qw 65000 \
    && fail "the route server's AS 65000 appears in the reverse-reflected route"
echo "$DETAIL_C1" | grep -q "$C2_IP" \
    || fail "the reverse reflection's next hop is not c2's $C2_IP: $(echo "$DETAIL_C1" | grep -A3 '65002')"
echo "$DETAIL_C1" | grep -q 'best (' \
    || fail "the reverse-reflected route is not the best path"
# And the refresh answer did not leak c1's own route back to it:
# c1 holds exactly one path for $REFLECTED — its own, "(unspec)"
# peer (origin-peer floor; a leak would surface as a second path
# carrying the RS's peer id).
LEAK=$(docker exec "$C1" sh -c "vtysh -c 'show bgp ipv4 unicast $REFLECTED json'" \
    | grep -o '"peerId"' | wc -l | tr -d ' ')
[ "$LEAK" = 1 ] \
    || fail "c1 holds $LEAK paths for its own $REFLECTED (origin-peer floor violated)"

echo "==> RS-KERNEL-CLEAN: the route server installed nothing"
sleep 3
docker exec "$RS" sh -c "ip route show proto bgp" | grep -q . \
    && fail "proto bgp route appeared in the RS kernel (RS RIB must stay separate)"
docker exec "$RS" sh -c "grep 'zapi: route add' $ROUSTERD_LOG" | grep -q "$REFLECTED" \
    && fail "rousterd programmed the reflected route into the kernel"
docker exec "$RS" sh -c "grep 'zapi: route add' $ROUSTERD_LOG" | grep -q "$EXCHANGED" \
    && fail "rousterd programmed the reverse-reflected route into the kernel"

echo "==> final state"
docker exec "$C2" sh -c "vtysh -c 'show bgp ipv4 unicast'"
docker exec "$C1" sh -c "vtysh -c 'show bgp ipv4 unicast'"
docker exec "$RS" sh -c "ip route show proto bgp; echo '(RS kernel, must be empty)'"

echo "bgp-rs interop: PASS"
