#!/usr/bin/env bash
# BFD-zapi end-to-end smoke (W1-b milestone 5): the full dynamic-session
# feed over the wire-pinned protocol —
#
#   w1b-s1: rousterd (ZAPI server on /var/run/frr/zserv.api)
#           + rouster bfdd --zapi (the BFD daemon role)
#           + a REAL FRR 10.2.2 bgpd with `neighbor ... bfd`
#   w1b-s2: real FRR zebra + mgmtd + real FRR bfdd (config peer)
#
# Machine checks (script exit 0):
#   - REGISTER-RELAYED:  bgpd's `neighbor <s2> bfd` reached rousterd
#                        (its log records the BFD destination command)
#                        and was relayed to the rouster bfdd.
#   - DYNAMIC-SESSION:   rouster bfdd created the dynamic session (its
#                        log) and it reaches Up against the REAL FRR
#                        bfdd (both status surfaces: `state Up` here,
#                        `Status: up` via vtysh there).
#   - BGPD-SEES-BFD:     bgpd's neighbor carries live BFD state (show
#                        output names the session up).
#   - DOWN-FANOUT:       `docker kill w1b-s2` (vanishing peer) expires
#                        the session (RFC 5880 §6.8.8); the DOWN report
#                        reaches bgpd through rousterd's 26 fan-out
#                        (bgpd's BFD status flips to down).
#   - SELF-CLEANING:     no w1b-s1/w1b-s2 containers remain (trap).
#
# Never pulls images (15 s-bounded cached probe); caps as the z5
# family. Captures to the quarantine dir on success AND failure.
#
#   scripts/test-bfd-zapi.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

S1=w1b-s1
S2=w1b-s2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BFDD_CONF=/tmp/bfdd.conf
BFDD_LOG=/tmp/bfdd.log
BFDD_STATUS=/tmp/bfdd.status
BGPD_LOG=/tmp/bgpd.log
MGMTD_LOG=/tmp/mgmtd.log
S2_BFDD_LOG=/tmp/frr-bfdd.log
S2_ZEBRA_LOG=/tmp/zebra.log
S2_MGMTD_LOG=/tmp/mgmtd.log
QUARANTINE="${ROUSTER_W1B_QUARANTINE:-$(CDPATH= cd -- "$(dirname -- "$0")/../away" && pwd)/2026-10-11/weekend/quarantine/bfd-zapi/smoke}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# Cached-images-only docker probe, 15 s-bounded (no pulls).
if ! perl -e 'alarm 15; exec @ARGV' docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "FAIL: docker image $IMAGE not available (no pulls allowed; the probe timed out or errored)" >&2
    exit 1
fi

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE"
    docker cp "$S1:$ROUSTERD_LOG" "$QUARANTINE/rousterd.log" 2>/dev/null || true
    docker cp "$S1:$BFDD_LOG" "$QUARANTINE/rouster-bfdd.log" 2>/dev/null || true
    docker cp "$S1:$BFDD_STATUS" "$QUARANTINE/rouster-bfdd.status" 2>/dev/null || true
    docker cp "$S1:$BGPD_LOG" "$QUARANTINE/bgpd.log" 2>/dev/null || true
    docker cp "$S2:$S2_BFDD_LOG" "$QUARANTINE/frr-bfdd.log" 2>/dev/null || true
    docker cp "$S2:$S2_ZEBRA_LOG" "$QUARANTINE/zebra.log" 2>/dev/null || true
    docker exec "$S2" sh -c "vtysh -d bfdd -c 'show bfd peers'" \
        > "$QUARANTINE/frr-bfd-peers.txt" 2>&1 || true
    docker exec "$S1" sh -c "vtysh -d bgpd -c 'show bgp neighbors'" \
        > "$QUARANTINE/bgpd-neighbors.txt" 2>&1 || true
    docker exec "$S1" sh -c "ls -l $ZAPI_SOCK; pidof rousterd bfdd bgpd mgmtd" \
        > "$QUARANTINE/env.txt" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    for side in "$S1" "$S2"; do
        echo "--- $side rousterd/bfdd tails ---" >&2
        docker exec "$side" sh -c "tail -20 $ROUSTERD_LOG $BFDD_LOG 2>/dev/null" >&2 || true
        echo "--- $side frr tails ---" >&2
        docker exec "$side" sh -c "tail -10 $BGPD_LOG $S2_BFDD_LOG 2>/dev/null" >&2 || true
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
    fail "$desc (waited ${attempts}s)"
}

trap 'capture; docker rm -f "$S1" "$S2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$S1" "$S2" >/dev/null 2>&1 || true

echo "==> building rousterd + bfdd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bfdd

echo "==> starting containers $S1 (rouster stack) and $S2 (FRR peer)"
for name in "$S1" "$S2"; do
    docker run -d --name "$name" --init \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
done
docker cp "target/$MUSL_TARGET/release/rousterd" "$S1:/usr/local/bin/rousterd"
docker cp "target/$MUSL_TARGET/release/bfdd" "$S1:/usr/local/bin/bfdd"

S1_IP=$(bridge_ip "$S1")
S2_IP=$(bridge_ip "$S2")
echo "==> bridge addresses: s1=$S1_IP (rouster) s2=$S2_IP (FRR)"

echo "==> s1: rousterd (ZAPI server) + rouster bfdd --zapi + mgmtd + REAL bgpd"
docker exec "$S1" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$S1" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$S1" "rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$S1" "zapi socket" 10 "test -S $ZAPI_SOCK"

# The rouster bfdd: empty config (sessions arrive dynamically), the
# zapi edge claims the daemon role and serves forwarded registrations.
docker exec "$S1" sh -c "printf '\n' > $BFDD_CONF"
docker exec -d "$S1" sh -c "bfdd --config $BFDD_CONF --zapi $ZAPI_SOCK --pidfile /tmp/bfdd.pid --status-file $BFDD_STATUS > $BFDD_LOG 2>&1"
wait_in "$S1" "rouster bfdd up" 15 "grep -q 'bfdd zapi: connected' $BFDD_LOG"

docker exec "$S1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG"
wait_in "$S1" "s1 mgmtd vty" 20 "test -S /var/run/frr/mgmtd.vty"
# bgpd's bfd registration fires reliably in the MULTIHOP + update-source
# form (the pinned trigger: _bfd_sess_valid demands a local address for
# multihop, and bgpd classifies NHT-unresolved neighbors as multihop —
# W1-b pinned-doc finding; an on-link `neighbor X bfd` never registered
# against rousterd in-window either). ebgp-multihop over the one-hop
# bridge is legal (RFC 5883 carries it; TTL 255 satisfies it).
docker exec -i "$S1" sh -c 'cat > /etc/frr/bgpd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname w1b-s1
router bgp 65000
 bgp router-id $S1_IP
 neighbor $S2_IP remote-as 65000
 neighbor $S2_IP ebgp-multihop 2
 neighbor $S2_IP update-source $S1_IP
 neighbor $S2_IP bfd
EOF
docker exec "$S1" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$S1" "s1 bgpd vty" 30 "test -S /var/run/frr/bgpd.vty"
docker exec "$S1" sh -c "vtysh -d bgpd -c 'conf t' -c 'debug bgp bfd'" || true

echo "==> s2: real FRR zebra + mgmtd + real bfdd (config peer, 100 ms x3)"
docker exec "$S2" sh -c "printf '%s\n' 'hostname w1b-s2' > /etc/frr/zebra.conf"
docker exec "$S2" sh -c "/usr/lib/frr/zebra -d -f /etc/frr/zebra.conf --log file:$S2_ZEBRA_LOG --log-level debug"
wait_in "$S2" "s2 zserv socket" 15 "test -S $ZAPI_SOCK"
docker exec "$S2" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$S2_MGMTD_LOG"
wait_in "$S2" "s2 mgmtd vty" 20 "test -S /var/run/frr/mgmtd.vty"
docker exec -i "$S2" sh -c 'cat > /etc/frr/bfdd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname w1b-s2
bfd
 peer $S1_IP multihop local-address $S2_IP
  detect-multiplier 3
  transmit-interval 100
  receive-interval 100
EOF
docker exec "$S2" sh -c "/usr/lib/frr/bfdd -d -f /etc/frr/bfdd.conf -z $ZAPI_SOCK --log file:$S2_BFDD_LOG --log-level debug"
wait_in "$S2" "s2 bfdd vty" 20 "test -S /var/run/frr/bfdd.vty"

echo "==> REGISTER-RELAYED: bgpd's neighbor bfd registration reached rousterd"
wait_in "$S1" "rousterd saw the BFD destination command" 30 \
    "grep -q 'BFD destination command' $ROUSTERD_LOG"
wait_in "$S1" "rousterd relayed to the daemon" 30 \
    "grep -q 'relaying BFD command to daemon' $ROUSTERD_LOG"
docker exec "$S1" sh -c "grep -q \"dst=$S2_IP\" $ROUSTERD_LOG" \
    || fail "the registration names s2's address ($S2_IP)"

echo "==> DYNAMIC-SESSION: rouster bfdd created it; both sides Up"
wait_in "$S1" "dynamic session created" 15 "grep -q 'dynamic session created' $BFDD_LOG"
wait_in "$S1" "rouster side Up" 30 "grep -q 'state Up' $BFDD_STATUS"
docker exec "$S1" sh -c "grep -q 'peer $S2_IP state Up' $BFDD_STATUS" \
    || fail "the dynamic session for $S2_IP is not Up"
wait_in "$S2" "FRR side Up" 30 "vtysh -d bfdd -c 'show bfd peers' | grep -q 'Status: up'"

echo "==> BGPD-SEES-BFD: bgpd's neighbor carries live BFD state"
wait_in "$S1" "bgpd neighbor BFD up" 15 \
    "vtysh -d bgpd -c 'show bgp neighbors $S2_IP' | grep -A2 BFD | grep -qi 'status: up'"

echo "==> DOWN-FANOUT: kill s2 (vanishing peer) - DOWN must reach bgpd"
sleep 3
docker kill "$S2" >/dev/null
wait_in "$S1" "rouster side Down" 15 "grep -q 'state Down' $BFDD_STATUS"
wait_in "$S1" "bgpd neighbor BFD down" 20 \
    "vtysh -d bgpd -c 'show bgp neighbors $S2_IP' | grep -A2 BFD | grep -qi 'status: down'"

echo "==> final state"
docker exec "$S1" sh -c "vtysh -d bgpd -c \"show bgp neighbors $S2_IP\" | grep -A6 'BFD:'" || true
capture

echo "bfd zapi smoke: PASS"
