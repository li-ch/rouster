#!/usr/bin/env bash
# W1-b pin-capture session (2026-10-11): pins the ZAPI BFD message
# family (cmds 26-30 era) against real FRR 10.2.2 speakers. Two phases:
#
#  Phase A (masquerade, client->zebra side): zapi-sniff stands in for
#    zebra; a REAL bfdd and a REAL bgpd are pointed at it via -z, and
#    vtysh pushes a `bfd` peer stanza + `router bgp` with `neighbor ...
#    bfd` — captures the exact bytes of ZEBRA_BFD_DEST_REGISTER (27)
#    and whatever else the daemons emit (bfdd's own zclient burst,
#    BFD_CLIENT_REGISTER 36, deregisters on config removal).
#
#  Phase B (real stack, zebra->client side): real zebra + mgmtd + real
#    bfdd in one container, a rouster bfdd (musl) as the UDP peer in a
#    second; zapi-bfd-probe (the client twin, zapi-notify-probe
#    pattern) connects to the REAL zserv socket, sends the pinned
#    BFD_CLIENT_REGISTER + BFD_DEST_REGISTER bytes, and records every
#    frame zebra pushes back when the session goes Up (peer container
#    alive) and Down (docker kill) — the ZEBRA_INTERFACE_BFD_DEST_
#    UPDATE (26) / ZEBRA_BFD_DEST_UPDATE (29) bodies.
#
# Debug capture tool, not a product smoke: the pins live in the
# analysis of the quarantine logs (docs/interop/zapi-10.2-pinned.md).
# Never pulls images (15 s-bounded cached probe); caps as the z5
# family; self-cleaning.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

CA=w1b-cap-a
CB1=w1b-cap-b1
CB2=w1b-cap-b2
IMAGE=frr-testbed:10.2.2
FRR_CONF=/etc/frr/frr.conf
# Repo-root cd + /away suffix: cd-ing into away/ races its own mkdir
# and fails on a fresh checkout (CI run 38647649951 lesson).
QUARANTINE="${ROUSTER_W1B_QUARANTINE:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/away/2026-10-11/weekend/quarantine/bfd-zapi}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

trap 'docker rm -f "$CA" "$CB1" "$CB2" >/dev/null 2>&1 || true' EXIT

# Cached-images-only docker probe, 15 s-bounded (no pulls).
perl -e 'alarm 15; exec @ARGV' docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "FAIL: docker image $IMAGE not available" >&2; exit 1; }
docker rm -f "$CA" "$CB1" "$CB2" >/dev/null 2>&1 || true

# The BFD target addresses: TEST-NET-2 (unreachable in Phase A — the
# REGISTER, not the session, is the pin; distinctive timers 250/300 x4
# so the byte fields are identifiable).
BFD_PEER=198.51.100.9
BFD_PEER2=198.51.100.10

mkdir -p "$QUARANTINE"

# IPv4 address of eth0 inside a container (docker default bridge).
bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

# Phase selector: `a` (masquerade only), `b` (real stack only), default
# both. Phase B's probe carries Phase A's pinned register bytes, so the
# first bring-up runs A, bakes the bytes into zapi-bfd-probe, then B.
PHASES="${1:-ab}"

if [[ "$PHASES" == *a* ]]; then

# ---------------------------------------------------------------------------
# Phase A — masquerade
# ---------------------------------------------------------------------------
echo "==> building zapi-sniff ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" --bin zapi-sniff
echo "==> Phase A: masquerade zebra (zapi-sniff) + real bfdd + real bgpd"
docker run -d --name "$CA" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/zapi-sniff" "$CA:/usr/local/bin/"

# The masquerade advertises the container's REAL eth0 so bgpd can arm
# SINGLE-HOP BFD (NHT-unresolved neighbors are treated as multihop and
# rejected by _bfd_sess_valid — W1-b live finding).
CA_IP=$(docker exec "$CA" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/\([0-9]*\).*/\1/p' | head -1)
CA_PLEN=$(docker exec "$CA" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/\([0-9]*\).*/\2/p' | head -1)
CA_GW=$(docker exec "$CA" sh -c "ip route show default" | sed -n 's/default via \([0-9.]*\).*/\1/p')
echo "==> A: container eth0=$CA_IP/$CA_PLEN gw=$CA_GW"

docker exec -d "$CA" sh -c "zapi-sniff --socket /tmp/zserv.api --log /root/sniff.log --respond-hello --hello-cmd 19 --respond-labelmgr --respond-iface eth0:2:$CA_IP/$CA_PLEN --respond-nht"
sleep 1
docker exec "$CA" sh -c "test -S /tmp/zserv.api" || { echo "sniff socket never appeared" >&2; exit 1; }

echo "==> A: real bfdd pointed at the masquerade, config via -f (vtysh -b
     pushes do not stick without mgmtd in this build — finding 4)"
docker exec -i "$CA" sh -c 'cat > /etc/frr/bfdd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname w1b-cap
bfd
 peer $BFD_PEER
  detect-multiplier 4
  transmit-interval 250
  receive-interval 300
EOF
docker exec "$CA" sh -c "/usr/lib/frr/bfdd -d -f /etc/frr/bfdd.conf -z /tmp/zserv.api --log file:/root/bfdd.log --log-level debug"
for _ in $(seq 1 20); do
    docker exec "$CA" sh -c "test -S /var/run/frr/bfdd.vty" && break
    sleep 1
done
docker exec "$CA" sh -c "test -S /var/run/frr/bfdd.vty" || { echo "bfdd vty never appeared" >&2; exit 1; }
sleep 3

echo "==> A: real bgpd pointed at the masquerade, config via -f
     (one on-link single-hop neighbor + one multihop with update-source)"
docker exec -i "$CA" sh -c 'cat > /etc/frr/bgpd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname w1b-cap
router bgp 65000
 bgp router-id $CA_IP
 neighbor $CA_GW remote-as 65000
 neighbor $CA_GW bfd
 neighbor $BFD_PEER remote-as 65000
 neighbor $BFD_PEER ebgp-multihop 5
 neighbor $BFD_PEER update-source $CA_IP
 neighbor $BFD_PEER bfd
EOF
docker exec "$CA" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /tmp/zserv.api --log file:/root/bgpd.log --log-level debug"
for _ in $(seq 1 20); do
    docker exec "$CA" sh -c "test -S /var/run/frr/bgpd.vty" && break
    sleep 1
done
docker exec "$CA" sh -c "test -S /var/run/frr/bgpd.vty" || { echo "bgpd vty never appeared" >&2; exit 1; }
sleep 12

echo "==> A: re-issue the multihop bfd command (an installed session UPDATEs, cmd 29)"
docker exec "$CA" sh -c "timeout 20 vtysh -d bgpd -c 'conf t' -c 'router bgp 65000' -c \"neighbor $BFD_PEER bfd\"" || true
sleep 5

echo "==> A: toggle the single-hop bfd off via vtysh -d bgpd (deregister pin)"
docker exec "$CA" sh -c "timeout 20 vtysh -d bgpd -c 'conf t' -c 'router bgp 65000' -c \"no neighbor $CA_GW bfd\"" || true
sleep 8

echo "==> A: capture evidence"
docker cp "$CA:/root/sniff.log" "$QUARANTINE/phase-a-sniff.log"
docker cp "$CA:/root/bfdd.log" "$QUARANTINE/phase-a-bfdd.log" || true
docker cp "$CA:/root/bgpd.log" "$QUARANTINE/phase-a-bgpd.log" || true
docker exec "$CA" sh -c "vtysh -d bfdd -c 'show bfd peers'; vtysh -d bgpd -c 'show bgp summary'" \
    > "$QUARANTINE/phase-a-state.txt" 2>&1 || true
docker rm -f "$CA" >/dev/null

echo "Phase A: DONE (analyze $QUARANTINE/phase-a-sniff.log)"
fi

# ---------------------------------------------------------------------------
# Phase B — real stack + probe
# ---------------------------------------------------------------------------
if [[ "$PHASES" == *b* ]]; then
echo "==> building zapi-bfd-probe + bfdd ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" --bin zapi-bfd-probe --bin bfdd
echo "==> Phase B: real zebra + mgmtd + real bfdd (b1) + rouster bfdd peer (b2)"
docker run -d --name "$CB1" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$CB2" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/zapi-bfd-probe" "$CB1:/usr/local/bin/"
docker cp "target/$MUSL_TARGET/release/bfdd" "$CB2:/usr/local/bin/"

B1_IP=$(bridge_ip "$CB1")
B2_IP=$(bridge_ip "$CB2")
echo "==> bridge addresses: b1=$B1_IP (FRR) b2=$B2_IP (rouster peer)"

docker exec "$CB1" sh -c "printf '%s\n' 'hostname w1b-b1' > /etc/frr/zebra.conf"
docker exec "$CB1" sh -c "/usr/lib/frr/zebra -d -f /etc/frr/zebra.conf --log file:/root/zebra.log --log-level debug"
for _ in $(seq 1 15); do
    docker exec "$CB1" sh -c "test -S /var/run/frr/zserv.api" && break
    sleep 1
done
docker exec "$CB1" sh -c "test -S /var/run/frr/zserv.api" || { echo "zebra socket never appeared" >&2; exit 1; }
docker exec "$CB1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/root/mgmtd.log"
for _ in $(seq 1 20); do
    docker exec "$CB1" sh -c "test -S /var/run/frr/mgmtd.vty" && break
    sleep 1
done
docker exec "$CB1" sh -c "/usr/lib/frr/bfdd -d -z /var/run/frr/zserv.api --log file:/root/bfdd.log --log-level debug"
for _ in $(seq 1 20); do
    docker exec "$CB1" sh -c "test -S /var/run/frr/bfdd.vty" && break
    sleep 1
done

echo "==> B: rouster bfdd peer stanza on b2 (100 ms x3)"
docker exec -i "$CB2" sh -c 'cat > /tmp/bfdd.conf' <<EOF
peer $B1_IP
  transmit-interval 100
  receive-interval 100
EOF
docker exec -d "$CB2" sh -c "bfdd --config /tmp/bfdd.conf --pidfile /tmp/bfdd.pid --status-file /tmp/bfdd.status > /tmp/bfdd.log 2>&1"
for _ in $(seq 1 10); do
    docker exec "$CB2" sh -c "test -f /tmp/bfdd.status" && break
    sleep 1
done

echo "==> B: resident zapi-bfd-probe against the REAL zebra (50 s window)"
docker exec -d "$CB1" sh -c "zapi-bfd-probe --socket /var/run/frr/zserv.api --log /root/bfd-probe.log --peer $B2_IP --secs 50"
sleep 5

echo "==> B: waiting for the FRR bfdd session (probe-registered) to come Up"
for _ in $(seq 1 30); do
    docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers' | grep -q 'Status: up'" && break
    sleep 1
done
docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers'" | tee "$QUARANTINE/phase-b-peers-up.txt"
sleep 5

echo "==> B: kill the rouster peer container (vanishing peer -> Down push)"
docker kill "$CB2" >/dev/null
sleep 10
docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers'" | tee "$QUARANTINE/phase-b-peers-down.txt" || true

echo "==> B: second probe window with a mid-window DEREGISTER (28)"
docker exec -d "$CB1" sh -c "zapi-bfd-probe --socket /var/run/frr/zserv.api --log /root/bfd-probe2.log --peer 203.0.113.9 --secs 20 --deregister-at 8"
sleep 24
docker cp "$CB1:/root/bfd-probe2.log" "$QUARANTINE/phase-b-probe-dereg.log" || true

echo "==> B: capture evidence"
sleep 5
docker cp "$CB1:/root/bfd-probe.log" "$QUARANTINE/phase-b-probe.log"
docker cp "$CB1:/root/zebra.log" "$QUARANTINE/phase-b-zebra.log" || true
docker cp "$CB1:/root/bfdd.log" "$QUARANTINE/phase-b-frr-bfdd.log" || true
docker cp "$CB2:/tmp/bfdd.status" "$QUARANTINE/phase-b-rouster-bfdd.status" 2>/dev/null || true
docker cp "$CB2:/tmp/bfdd.log" "$QUARANTINE/phase-b-rouster-bfdd.log" 2>/dev/null || true

echo "Phase B: DONE (analyze $QUARANTINE/phase-b-probe.log)"
fi

# ---------------------------------------------------------------------------
# Phase C — bfdd's own session-state messages (masquerade + live peer)
# ---------------------------------------------------------------------------
if [[ "$PHASES" == *c* ]]; then
echo "==> building zapi-sniff + bfdd ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" --bin zapi-sniff --bin bfdd
echo "==> Phase C: masquerade zebra + real bfdd (c1) + rouster bfdd peer (c2)"
docker run -d --name "$CB1" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$CB2" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/zapi-sniff" "$CB1:/usr/local/bin/"
docker cp "target/$MUSL_TARGET/release/bfdd" "$CB2:/usr/local/bin/"
C1_IP=$(bridge_ip "$CB1")
C2_IP=$(bridge_ip "$CB2")
echo "==> bridge addresses: c1=$C1_IP (FRR bfdd) c2=$C2_IP (rouster peer)"

docker exec -d "$CB1" sh -c "zapi-sniff --socket /tmp/zserv.api --log /root/sniff.log --respond-hello --hello-cmd 19 --respond-labelmgr"
sleep 1
docker exec -i "$CB1" sh -c 'cat > /etc/frr/bfdd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname w1b-c1
bfd
 peer $C2_IP
  detect-multiplier 3
  transmit-interval 100
  receive-interval 100
EOF
docker exec "$CB1" sh -c "/usr/lib/frr/bfdd -d -f /etc/frr/bfdd.conf -z /tmp/zserv.api --log file:/root/bfdd.log --log-level debug"
for _ in $(seq 1 20); do
    docker exec "$CB1" sh -c "test -S /var/run/frr/bfdd.vty" && break
    sleep 1
done

docker exec -i "$CB2" sh -c 'cat > /tmp/bfdd.conf' <<EOF
peer $C1_IP
  transmit-interval 100
  receive-interval 100
EOF
docker exec -d "$CB2" sh -c "bfdd --config /tmp/bfdd.conf --pidfile /tmp/bfdd.pid --status-file /tmp/bfdd.status > /tmp/bfdd.log 2>&1"
for _ in $(seq 1 15); do
    docker exec "$CB2" sh -c "test -f /tmp/bfdd.status" && break
    sleep 1
done

echo "==> C: waiting for the session to come Up, then killing the peer"
for _ in $(seq 1 30); do
    docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers' | grep -q 'Status: up'" && break
    sleep 1
done
sleep 5
docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers'" > "$QUARANTINE/phase-c-peers-up.txt" || true
docker kill "$CB2" >/dev/null
sleep 8
docker exec "$CB1" sh -c "vtysh -d bfdd -c 'show bfd peers'" > "$QUARANTINE/phase-c-peers-down.txt" || true
sleep 2

echo "==> C: capture evidence"
docker cp "$CB1:/root/sniff.log" "$QUARANTINE/phase-c-sniff.log"
docker cp "$CB1:/root/bfdd.log" "$QUARANTINE/phase-c-frr-bfdd.log" || true
docker cp "$CB2:/tmp/bfdd.log" "$QUARANTINE/phase-c-rouster-bfdd.log" 2>/dev/null || true
echo "Phase C: DONE (analyze $QUARANTINE/phase-c-sniff.log)"
fi
