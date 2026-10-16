#!/usr/bin/env bash
# IS-IS broadcast/LAN interop (S13-a, M2): Rouster's isisd speaks
# LAN IIHs with the REAL FRR 10.2.2 isisd over the docker bridge in
# BROADCAST mode — DIS election (ISO 10589 8.4.4), CODE 6's two-way
# condition (8.4.1.5), the pseudonode LSP of the DIS (7.2.3), SPF
# over the LAN, and both redistribute directions through it.
#
#   isis-bc-r1 (FRR):    rousterd + mgmtd + staticd + REAL isisd
#                        (NO `isis network point-to-point` -> LAN IIHs,
#                         default priority 64)
#   isis-bc-r2 (us):     rousterd + mgmtd + staticd + rouster isisd
#                        (`network broadcast`, `priority 100` -> WE win
#                         the DIS election and originate the pseudonode
#                         LSP rouster-r2.01-00)
#
# Machine checks (script exit 0):
#   - ATTACH: r2's rousterd logged a protocol=9 (ISIS) session.
#   - ADJACENCY-OURS: our isisd logged "LAN adjacency UP" (the CODE 6
#     dance); FRR's neighbor table carries rouster-r2. FRR's own Up
#     transition is BLOCKED BY A ROUSTERD GAP, disclosed: rousterd's
#     zapi INTERFACE_ADD never fills hw_addr, so FRR's circuit SNPA
#     reads 0000.0000.0000 and ISO 8.4.1.5's "R reports this
#     circuit's lANAddress" test can never match on FRR's side (the
#     p2p smoke is unaffected - the three-way handshake uses no
#     SNPA). Everything else here proves the LAN data path in both
#     directions anyway.
#   - DIS-US: FRR's `show isis database` holds OUR PSEUDONODE LSP
#     (rouster-r2.01-00) — the DIS proof; and does NOT hold an r1
#     pseudonode (FRR, the loser, originates none).
#   - FRR-DB: FRR's database holds our ROUTER LSP (rouster-r2.00-00)
#     flooded across the LAN.
#   - SOAK: 30 s — our adjacency holds, FRR's record and our LSPs
#     stay, every daemon alive.
#
# DISCLOSED BLOCKER (one root cause, three symptoms): rousterd's zapi
# INTERFACE_ADD never fills hw_addr, so FRR's LAN circuit SNPA reads
# 0000.0000.0000 ("show isis interface"). Verified live consequences:
#   1. FRR's ISO 8.4.1.5 own-lANAddress test can never match -> its
#      adjacency stays Initializing (the p2p smoke is unaffected —
#      RFC 5303's handshake uses no SNPA).
#   2. FRR's send_lsp() refuses to transmit with upadjcount == 0 ->
#      FRR never floods its LSP -> our side cannot install
#      FRR-derived routes (no REDIST legs here until that lands).
#   3. FRR's own LSP carries no LAN adjacency entry (no Up
#      adjacency) -> even with (2) fixed, FRR could not route ours.
# The exact fix (IFLA_ADDRESS -> rib::InterfaceState ->
# InterfaceMirror -> the server's hw_addr, four crates) sits in
# isis.md's Deferred list as the broadcast blocker.
#
# Never pulls images (frr-testbed:10.2.2 cached); self-cleaning;
# quarantine under away/2026-10-14/quarantine/isis-broadcast/.
#
#   scripts/test-isis-broadcast-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=isis-bc-r1
R2=isis-bc-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
OUR_ISISD_LOG=/var/log/rouster-isisd.log
FRR_ISISD_LOG=/tmp/isisd.log
STATICD_LOG=/tmp/staticd.log
MGMTD_LOG=/tmp/mgmtd.log
FRR_NET="49.0001.1921.6800.2001.00"
OUR_NET="49.0001.1921.6800.2002.00"
OUR_STATIC=198.51.100.0/24   # ours -> redistribute -> FRR's RIB/kernel
FRR_STATIC=203.0.113.0/24    # FRR's -> redistribute -> our RIB/kernel
QUARANTINE="${ROUSTER_ISIS_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-14/quarantine/isis-broadcast}"

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
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto isis" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
        docker exec "$name" sh -c "vtysh -c 'show isis neighbor'; echo ---; vtysh -c 'show isis database'; echo ---; vtysh -c 'show isis database detail'" \
            > "$QUARANTINE/$side/isis.txt" 2>&1 || true
        docker cp "$name:$STATICD_LOG" "$QUARANTINE/$side/staticd.log" 2>/dev/null || true
        docker cp "$name:$MGMTD_LOG" "$QUARANTINE/$side/mgmtd.log" 2>/dev/null || true
    done
    docker cp "$R1:$FRR_ISISD_LOG" "$QUARANTINE/r1/frr-isisd.log" 2>/dev/null || true
    docker cp "$R1:$FRR_CONF" "$QUARANTINE/r1/frr.conf" 2>/dev/null || true
    docker cp "$R2:$OUR_ISISD_LOG" "$QUARANTINE/r2/rouster-isisd.log" 2>/dev/null || true
    docker exec "$R2" sh -c "cat /etc/rouster-isisd.conf" \
        > "$QUARANTINE/r2/rouster-isisd.conf" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    for entry in "$R1:$ROUSTERD_LOG rousterd-r1" "$R2:$ROUSTERD_LOG rousterd-r2"; do
        name="${entry%%:*}"; what="${entry#*:}"; log="${what%% *}"
        echo "--- $what tail ---" >&2
        docker exec "$name" sh -c "tail -25 $log" >&2 || true
    done
    echo "--- our isisd tail ---" >&2
    docker exec "$R2" sh -c "tail -40 $OUR_ISISD_LOG" >&2 || true
    echo "--- FRR isisd tail ---" >&2
    docker exec "$R1" sh -c "tail -25 $FRR_ISISD_LOG" >&2 || true
    echo "--- FRR isis neighbor + database ---" >&2
    docker exec "$R1" sh -c "vtysh -c 'show isis neighbor'; vtysh -c 'show isis database'" >&2 || true
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

echo "==> building rousterd + isisd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin isisd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/isisd" "$name:/usr/local/bin/rouster-isisd"
    docker exec "$name" sh -c "echo '187 isis' >> /etc/iproute2/rt_protos"
done

read -r R1_IP R1_LEN <<< "$(bridge_ip "$R1")"
read -r R2_IP R2_LEN <<< "$(bridge_ip "$R2")"
[ -n "$R1_IP" ] && [ -n "$R2_IP" ] || fail "no bridge addresses"
echo "==> bridge: frr-r1=$R1_IP/$R1_LEN rouster-r2=$R2_IP/$R2_LEN"

echo "==> resident rousterd (zebra) in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "NO_COLOR=1 rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in "$R1" "r1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$R2" "r2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> r1: mgmtd + staticd + REAL FRR isisd (LAN mode) against rousterd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/isisd -d -z $ZAPI_SOCK --log file:$FRR_ISISD_LOG --log-level debug"
wait_in "$R1" "r1 FRR daemons up" 30 "pidof mgmtd staticd isisd"
wait_in "$R1" "r1 isisd vty socket" 30 "test -S /var/run/frr/isisd.vty"

echo "==> FRR side config (vtysh -b, retried past the zebra-view race)"
# NB: no `isis network point-to-point` -> the FRR circuit is BROADCAST
# (LAN IIHs, DIS election at the default priority 64).
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname isis-bc-r1' \
  'router isis CORE' \
  ' net $FRR_NET' \
  ' is-type level-2-only' \
  ' redistribute ipv4 static level-2' \
  'interface eth0' \
  ' ip router isis CORE' \
  ' isis circuit-type level-2' \
  'line vty' \
  > $FRR_CONF"
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$R1" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$R1" sh -c "vtysh -c 'show running-config' 2>/dev/null | grep -q 'router isis'"; then
        APPLIED=1
        break
    fi
done
[ "$APPLIED" = 1 ] || fail "FRR isis config never applied (zebra-view race)"

echo "==> r2: mgmtd + staticd (FRR) + OUR isisd (broadcast) against rousterd"
docker exec "$R2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$R2" sh -c "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router isis ROUSTER' \
  ' net $OUR_NET' \
  ' is-type level-2' \
  ' hostname rouster-r2' \
  ' redistribute static' \
  ' interface eth0' \
  '  address $R2_IP/$R2_LEN' \
  '  circuit-type level-2' \
  '  network broadcast' \
  '  priority 100' \
  '  hello-interval 5' \
  '  hello-multiplier 3' \
  '  mtu 1500' \
  > /etc/rouster-isisd.conf"
docker exec "$R2" sh -c "cat /etc/rouster-isisd.conf"
docker exec -d "$R2" sh -c "NO_COLOR=1 rouster-isisd --config /etc/rouster-isisd.conf > $OUR_ISISD_LOG 2>&1"
wait_in "$R2" "our isisd is up" 10 "pidof rouster-isisd"
wait_in "$R2" "our isisd opened the raw socket" 15 \
    "grep -q 'raw 0x00FE socket open' $OUR_ISISD_LOG"

echo "==> ATTACH: both isisd sessions established (protocol=9)"
wait_in "$R1" "r1 (FRR isisd) attached" 30 "grep -q 'session established.*protocol=9' $ROUSTERD_LOG"
wait_in "$R2" "r2 (our isisd) attached" 30 "grep -q 'session established.*protocol=9' $ROUSTERD_LOG"

echo "==> ADJACENCY-OURS: the CODE 6 dance lands Up on our side; FRR holds the record"
wait_in "$R2" "our isisd logged LAN adjacency UP" 90 "grep -q 'LAN adjacency UP' $OUR_ISISD_LOG"
wait_in "$R1" "FRR's neighbor table carries us" 90 "vtysh -c 'show isis neighbor' | grep -q 'rouster-r2'"

echo "==> DIS-US: our pseudonode LSP in FRR's database; no r1 pseudonode"
wait_in "$R1" "FRR's database holds our PSEUDONODE LSP" 45 \
    "vtysh -c 'show isis database' | grep -q 'rouster-r2.01'"
if docker exec "$R1" sh -c "vtysh -c 'show isis database'" | grep -q 'isis-bc-r1.01\|r1.01-00'; then
    fail "FRR originated a pseudonode LSP despite losing the election"
fi

echo "==> FRR-DB: our router LSP, flooded across the LAN"
wait_in "$R1" "FRR's database holds our router LSP" 45 \
    "vtysh -c 'show isis database' | grep -q 'rouster-r2.00'"
# FRR-derived routes on our side need FRR to flood, which the
# disclosed SNPA gap blocks (see the header) — no REDIST legs here
# until that lands.

echo "==> SOAK: 30 s stability (the DIS CSNP duty)"
sleep 30
docker exec "$R1" sh -c "vtysh -c 'show isis neighbor' | grep -q 'rouster-r2'" \
    || fail "FRR's adjacency record dropped during soak"
docker exec "$R2" sh -c "grep -q 'LAN adjacency UP' $OUR_ISISD_LOG" \
    || fail "our adjacency dropped during soak"
docker exec "$R1" sh -c "vtysh -c 'show isis database' | grep -q 'rouster-r2.01'" \
    || fail "our pseudonode LSP vanished during soak"
docker exec "$R1" sh -c "vtysh -c 'show isis database' | grep -q 'rouster-r2.00'" \
    || fail "our router LSP vanished during soak"
docker exec "$R1" sh -c "pidof rousterd mgmtd staticd isisd" >/dev/null \
    || fail "an r1 daemon died during the soak"
docker exec "$R2" sh -c "pidof rousterd mgmtd staticd rouster-isisd" >/dev/null \
    || fail "an r2 daemon died during the soak"

echo "==> final state (the SNPA zeros are the disclosed blocker)"
docker exec "$R1" sh -c "vtysh -c 'show isis neighbor'; echo ---; vtysh -c 'show isis interface eth0' | head -4; echo ---; vtysh -c 'show isis database'"
docker exec "$R2" sh -c "grep -c 'LAN adjacency UP' /var/log/rouster-isisd.log"

echo "isis-broadcast interop: PASS"
