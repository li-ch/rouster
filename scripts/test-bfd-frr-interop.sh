#!/usr/bin/env bash
# BFD interop (P2-a milestone 5): a real FRR 10.2.2 bfdd (with its own
# native zebra + mgmtd) peers with Rouster's bfdd over the docker
# bridge — pure peer-to-peer UDP 3784, no zapi between the two BFD
# speakers (Rouster bfdd's zapi edge is deliberately §Deferred).
#
#   bfd-r1: /usr/lib/frr/zebra + mgmtd + bfdd   (the FRR half)
#   bfd-r2: rouster bfdd (musl static, docker cp)
#
# Machine checks (script exit 0):
#   - PEER-UP-FRR:   `vtysh -c 'show bfd peers'` on r1 reports
#                    "Status: up" for r2's bridge address.
#   - PEER-UP-OURS:  r2's published status file (A21) reports
#                    "state Up" with r1's discriminator learned, and
#                    the bfdd log carries the RFC-named transitions
#                    (Down -> Init, Init -> Up).
#   - STATE-DOWN:    after `docker kill bfd-r2` (a vanished peer — no
#                    AdminDown), r1's bfdd must report "Status: down"
#                    within its Detection Time (timers 100 ms x3 on
#                    both sides; RFC 5880 §6.8.8 expiry, not a
#                    teardown signal).
#   - SELF-CLEANING: no bfd-r1/bfd-r2 containers remain after either
#                    run (trap).
#
# Never pulls images (15 s-bounded probe; cached frr-testbed:10.2.2
# only). Caps as the z5 family (NET_ADMIN/NET_RAW/SYS_ADMIN). Logs and
# both sides' status surfaces captured to the quarantine dir on
# success AND failure (absolute path — the S5 lesson).
#
#   scripts/test-bfd-frr-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=bfd-r1
R2=bfd-r2
IMAGE=frr-testbed:10.2.2
FRR_CONF=/etc/frr/frr.conf
BFDD_LOG=/tmp/bfdd.log
BFDD_CONF=/tmp/bfdd.conf
BFDD_STATUS=/tmp/bfdd.status
FRR_BFDD_LOG=/tmp/frr-bfdd.log
ZEBRA_LOG=/tmp/zebra.log
MGMTD_LOG=/tmp/mgmtd.log
# Absolute quarantine path (S5): the away program's evidence dir
# (overridable for debug runs that must inspect the captures). The cd
# anchors on the repo root (always present on a fresh checkout) and
# appends away/ — cd-ing into away/ itself runs before the mkdir below
# and dies on a fresh tree (the CI run 38647649951 lesson).
QUARANTINE="${ROUSTER_BFD_QUARANTINE:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/away/2026-10-11/quarantine/bfd}"

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

# IPv4 address of eth0 inside a container (docker default bridge).
bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$R1" sh -c "vtysh -c 'show bfd peers'" \
        > "$QUARANTINE/frr-bfd-peers.txt" 2>&1 || true
    docker cp "$R1:$FRR_BFDD_LOG" "$QUARANTINE/frr-bfdd.log" 2>/dev/null || true
    docker cp "$R1:$ZEBRA_LOG" "$QUARANTINE/zebra.log" 2>/dev/null || true
    docker cp "$R1:$MGMTD_LOG" "$QUARANTINE/mgmtd.log" 2>/dev/null || true
    docker cp "$R2:$BFDD_LOG" "$QUARANTINE/rouster-bfdd.log" 2>/dev/null || true
    docker cp "$R2:$BFDD_STATUS" "$QUARANTINE/rouster-bfdd.status" 2>/dev/null || true
    docker exec "$R1" sh -c "ls -l /var/run/frr/zserv.api; pidof zebra mgmtd bfdd" \
        > "$QUARANTINE/env.txt" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    echo "--- r1 frr bfdd tail ---" >&2
    docker exec "$R1" sh -c "tail -20 $FRR_BFDD_LOG" >&2 || true
    echo "--- r2 rouster bfdd tail ---" >&2
    docker exec "$R2" sh -c "tail -20 $BFDD_LOG" >&2 || true
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

trap 'capture; docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true' EXIT
docker rm -f "$R1" "$R2" >/dev/null 2>&1 || true

echo "==> building rouster bfdd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin bfdd

echo "==> starting containers $R1 (FRR) and $R2 (rouster) from $IMAGE"
for name in "$R1" "$R2"; do
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
done
docker cp "target/$MUSL_TARGET/release/bfdd" "$R2:/usr/local/bin/bfdd"

R1_IP=$(bridge_ip "$R1")
R2_IP=$(bridge_ip "$R2")
echo "==> bridge addresses: r1=$R1_IP (FRR) r2=$R2_IP (rouster)"

echo "==> FRR half: zebra (native zapi server) + mgmtd + REAL bfdd"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname bfd-r1' \
  'bfd' \
  ' peer $R2_IP' \
  '  detect-multiplier 3' \
  '  transmit-interval 100' \
  '  receive-interval 100' \
  > $FRR_CONF"
docker exec "$R1" sh -c "printf '%s\n' 'hostname bfd-r1' > /etc/frr/zebra.conf"
docker exec "$R1" sh -c "/usr/lib/frr/zebra -d -f /etc/frr/zebra.conf --log file:$ZEBRA_LOG --log-level debug"
wait_in "$R1" "r1 zserv socket" 15 "test -S /var/run/frr/zserv.api"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:$MGMTD_LOG --log-level debug"
wait_in "$R1" "r1 mgmtd vty socket" 20 "test -S /var/run/frr/mgmtd.vty"
docker exec "$R1" sh -c "/usr/lib/frr/bfdd -d -z /var/run/frr/zserv.api --log file:$FRR_BFDD_LOG --log-level debug"
wait_in "$R1" "r1 bfdd vty socket" 20 "test -S /var/run/frr/bfdd.vty"
docker exec "$R1" vtysh -b

echo "==> rouster half: bfdd with the peer stanza (100 ms x3)"
docker exec "$R2" sh -c "printf '%s\n' 'peer $R1_IP' '  transmit-interval 100' '  receive-interval 100' > $BFDD_CONF"
docker exec -d "$R2" sh -c "bfdd --config $BFDD_CONF --pidfile /tmp/bfdd.pid --status-file $BFDD_STATUS > $BFDD_LOG 2>&1"
wait_in "$R2" "r2 bfdd status published" 10 "test -f $BFDD_STATUS"

echo "==> waiting for BOTH sides to reach Up"
wait_in "$R1" "r1 (FRR) sees the session up" 30 \
    "vtysh -c 'show bfd peers' | grep -q 'Status: up'"
wait_in "$R2" "r2 (rouster) sees the session Up" 15 \
    "grep -q 'state Up' $BFDD_STATUS"
docker exec "$R2" sh -c "grep -q 'remote-discr 0' $BFDD_STATUS && exit 1 || exit 0" \
    || fail "r2 Up but the remote discriminator never learned (§6.8.6 step 13)"
docker exec "$R2" sh -c "grep -Eq 'Down -> (Init|Up)' $BFDD_LOG" \
    || fail "r2 log lacks the RFC-named transition into Up (§6.8.6 step 23)"

echo "==> stable both directions for 5 s, flap-free (the §6.8.2 reschedule)"
sleep 5
docker exec "$R1" sh -c "vtysh -c 'show bfd peers' | grep -q 'Status: up'" \
    || fail "r1 session not stably up"
docker exec "$R2" sh -c "grep -q 'state Up' $BFDD_STATUS" \
    || fail "r2 session not stably up"
docker exec "$R2" sh -c "grep -q 'Up -> Down' $BFDD_LOG" \
    && fail "r2 flapped after reaching Up (a transmission gap starved FRR's Detection Time)"
docker exec "$R2" sh -c "[ \"\$(grep -c -- '-> Up' $BFDD_LOG)\" = 1 ]" \
    || fail "r2 entered Up more than once (flap)"

echo "==> STATE-DOWN: killing r2 (vanishing peer, no AdminDown) - r1 must expire"
docker kill "$R2" >/dev/null
wait_in "$R1" "r1 (FRR) sees the session down after the kill" 15 \
    "vtysh -c 'show bfd peers' | grep -q 'Status: down'"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show bfd peers'"
capture

echo "bfd frr interop: PASS"
