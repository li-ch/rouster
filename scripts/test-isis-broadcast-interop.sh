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
#   - ADJACENCY-BOTH: FRR `show isis neighbor` Up AND our isisd logged
#     "LAN adjacency UP" (the CODE 6 dance).
#   - DIS-US: FRR's `show isis database` holds OUR PSEUDONODE LSP
#     (rouster-r2.01-00) — the DIS proof; and does NOT hold an r1
#     pseudonode (FRR, the loser, originates none).
#   - LSDB-BOTH: FRR's database holds our router LSP (rouster-r2.00-00)
#     with the LAN adjacency entry; our SPF installed an FRR-derived
#     route through the LAN.
#   - REDIST-OUT: staticd on r2 injects 198.51.100.0/24 -> our TLV 135
#     -> FRR's kernel `proto isis` via our bridge IP (across the LAN).
#   - REDIST-IN: FRR's static 203.0.113.0/24 -> our SPF -> r2 kernel
#     `proto isis` via FRR's bridge IP.
#   - SOAK: 30 s — adjacency still Up, routes still present, every
#     daemon alive.
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

echo "==> ADJACENCY-BOTH: waiting for Up on both sides (the CODE 6 dance)"
wait_in "$R1" "FRR neighbor Up" 90 "vtysh -c 'show isis neighbor' | grep -q ' Up '"
wait_in "$R2" "our isisd logged LAN adjacency UP" 90 "grep -q 'LAN adjacency UP' $OUR_ISISD_LOG"

echo "==> DIS-US: our pseudonode LSP in FRR's database; no r1 pseudonode"
wait_in "$R1" "FRR's database holds our PSEUDONODE LSP" 45 \
    "vtysh -c 'show isis database' | grep -q 'rouster-r2.01'"
if docker exec "$R1" sh -c "vtysh -c 'show isis database'" | grep -q 'isis-bc-r1.01\|r1.01-00'; then
    fail "FRR originated a pseudonode LSP despite losing the election"
fi

echo "==> LSDB-BOTH: each database holds the other's router LSP"
wait_in "$R1" "FRR's database holds our router LSP" 30 \
    "vtysh -c 'show isis database' | grep -q 'rouster-r2.00'"
wait_in "$R2" "our isisd installed FRR-derived routes over the LAN" 45 \
    "grep -q 'IS-IS route installed' $OUR_ISISD_LOG"

echo "==> REDIST-OUT: staticd injects $OUR_STATIC -> our TLV 135 -> FRR kernel via the LAN"
docker exec "$R2" vtysh -c "configure terminal" -c "ip route $OUR_STATIC $R1_IP"
wait_in "$R1" "FRR holds our prefix in its database" 45 \
    "vtysh -c 'show isis database detail' | grep -q '${OUR_STATIC%/*}'"
wait_in "$R1" "$OUR_STATIC in r1 kernel via ISIS" 45 \
    "ip route show proto isis | grep -q '$OUR_STATIC'"
docker exec "$R1" sh -c "ip route show proto isis | grep '$OUR_STATIC'" | grep -q "via $R2_IP" \
    || fail "FRR's ISIS route for $OUR_STATIC does not point at us ($R2_IP)"

echo "==> REDIST-IN: FRR's static -> FRR TLV 135 -> our SPF -> r2 kernel"
docker exec "$R1" vtysh -c "configure terminal" -c "ip route $FRR_STATIC blackhole"
wait_in "$R2" "our isisd installed FRR's prefix" 60 \
    "grep 'IS-IS route installed' $OUR_ISISD_LOG | grep -q '${FRR_STATIC%/*}'"
wait_in "$R2" "r2 rousterd exported it to the kernel" 45 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$FRR_STATIC'"
wait_in "$R2" "$FRR_STATIC in r2 kernel proto isis via FRR" 45 \
    "ip route show proto isis | grep '$FRR_STATIC' | grep -q 'via $R1_IP'"

echo "==> SOAK: 30 s adjacency/route stability (the DIS CSNP duty)"
sleep 30
docker exec "$R1" sh -c "vtysh -c 'show isis neighbor' | grep -q ' Up '" \
    || fail "FRR adjacency dropped during soak"
docker exec "$R2" sh -c "grep -q 'LAN adjacency UP' $OUR_ISISD_LOG" \
    || fail "our adjacency dropped during soak"
docker exec "$R1" sh -c "vtysh -c 'show isis database' | grep -q 'rouster-r2.01'" \
    || fail "our pseudonode LSP vanished during soak"
docker exec "$R2" sh -c "ip route show proto isis | grep -q '$FRR_STATIC'" \
    || fail "learned route lost during soak"
docker exec "$R1" sh -c "pidof rousterd mgmtd staticd isisd" >/dev/null \
    || fail "an r1 daemon died during the soak"
docker exec "$R2" sh -c "pidof rousterd mgmtd staticd rouster-isisd" >/dev/null \
    || fail "an r2 daemon died during the soak"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show isis neighbor'; echo ---; vtysh -c 'show isis database'; echo ---; ip route show proto isis"
docker exec "$R2" sh -c "ip route show proto isis"

echo "isis-broadcast interop: PASS"
