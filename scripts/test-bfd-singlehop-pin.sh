#!/usr/bin/env bash
# M1 pin-capture (2026-10-11 night): the bgpd-EMITTED single-hop
# ZEBRA_BFD_DEST_REGISTER (27) family against real FRR 10.2.2 — the
# W1-b §Deferred item (W1-b pinned the multihop frame; its single-hop
# leg was pinned only by Phase B acceptance, never by a bgpd-emitted
# capture).
#
# Two legs, one masquerade zebra (zapi-sniff) + real bgpd:
#
#  Leg 1 (bare masquerade, no interface/NHT answers): bgpd with an
#    on-link EBGP neighbor (the docker bridge gateway — no BGP speaker
#    there) arms single-hop BFD at config-apply time and emits the
#    REGISTER with NO ifname and the wildcard source. With interface
#    dumps and NHT answers deliberately ABSENT this also proves the
#    M1 source finding: bgpd's single/multi-hop classification is
#    PEER_IS_MULTIHOP (same-AS neighbor ⇒ iBGP ⇒ multihop; otherwise
#    ebgp-multihop/ttl-security), NOT an NHT property — the W1-b
#    "NHT-unresolved neighbors are treated as multihop" reading was a
#    misdiagnosis of a same-AS config (see the pinned doc's M1
#    addendum).
#
#  Leg 2 (full masquerade: interface dump + NHT answers): a REAL EBGP
#    peer (bgpd in a second container) establishes over the bridge;
#    on establishment bgpd re-arms the session with the learned local
#    address and egress interface — pinning the ifname-carrying
#    UPDATE (29), the DEREGISTER (28) of `no neighbor ... bfd` (the
#    first wire evidence for command 28), and the re-add REGISTER
#    (27, now with ifname + source).
#
# Debug capture tool, not a product smoke: the pins live in the
# analysis of the quarantine logs (docs/interop/zapi-10.2-pinned.md,
# M1 addendum). Never pulls images (15 s-bounded cached probe);
# self-cleaning.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

SA=m1-sh-a
SB=m1-sh-b
IMAGE=frr-testbed:10.2.2
QUARANTINE="${ROUSTER_M1_QUARANTINE:-$(CDPATH= cd -- "$(dirname -- "$0")/../away" && pwd)/2026-10-11/night/quarantine/bfd-singlehop}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

trap 'docker rm -f "$SA" "$SB" >/dev/null 2>&1 || true' EXIT

# Cached-images-only docker probe, 15 s-bounded (no pulls).
perl -e 'alarm 15; exec @ARGV' docker image inspect "$IMAGE" >/dev/null 2>&1 \
    || { echo "FAIL: docker image $IMAGE not available" >&2; exit 1; }
docker rm -f "$SA" "$SB" >/dev/null 2>&1 || true

mkdir -p "$QUARANTINE"

# IPv4 address / plen of eth0 inside a container (docker default bridge).
eth0_ip() { docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1; }
eth0_plen() { docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet [0-9.]*\/\([0-9]*\).*/\1/p' | head -1; }

wait_vty() { # container, vty name, tries
    local i
    for i in $(seq 1 "${3:-20}"); do
        docker exec "$1" sh -c "test -S /var/run/frr/$2.vty" && return 0
        sleep 1
    done
    echo "$2 vty never appeared in $1" >&2
    return 1
}

echo "==> building zapi-sniff ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" --bin zapi-sniff

echo "==> containers: $SA (bgpd under masquerade), $SB (real EBGP peer)"
docker run -d --name "$SA" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker run -d --name "$SB" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/zapi-sniff" "$SA:/usr/local/bin/"

SA_IP=$(eth0_ip "$SA"); SA_PLEN=$(eth0_plen "$SA")
SB_IP=$(eth0_ip "$SB")
SA_GW=$(docker exec "$SA" sh -c "ip route show default" | sed -n 's/default via \([0-9.]*\).*/\1/p')
echo "==> bridge: a=$SA_IP/$SA_PLEN gw=$SA_GW  b=$SB_IP"

# ---------------------------------------------------------------------------
# Leg 1 — bare masquerade; apply-time single-hop REGISTER, no ifname,
# wildcard source, with interface/NHT answers deliberately absent.
# ---------------------------------------------------------------------------
echo "==> 1: bare masquerade (hello + labelmgr only, NO iface/nht answers)"
docker exec -d "$SA" sh -c "zapi-sniff --socket /tmp/zserv-s1.api --log /root/sniff-s1.log --respond-hello --hello-cmd 19 --respond-labelmgr"
sleep 1
docker exec "$SA" sh -c "test -S /tmp/zserv-s1.api" \
    || { echo "sniff s1 socket never appeared" >&2; exit 1; }

echo "==> 1: bgpd with an on-link EBGP neighbor (the bridge gw, remote-as 65001)"
docker exec -i "$SA" sh -c 'cat > /etc/frr/bgpd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname m1-leg1
router bgp 65000
 bgp router-id $SA_IP
 neighbor $SA_GW remote-as 65001
 neighbor $SA_GW bfd
EOF
docker exec "$SA" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /tmp/zserv-s1.api --log file:/root/bgpd-s1.log --log-level debug"
wait_vty "$SA" bgpd
sleep 8
docker exec "$SA" sh -c "timeout 10 vtysh -d bgpd -c 'show bgp neighbor $SA_GW' | grep -i bfd" | tee "$QUARANTINE/leg1-neighbor-bfd.txt" || true
docker exec "$SA" sh -c "pkill -TERM bgpd" || true
sleep 2

# ---------------------------------------------------------------------------
# Leg 2 — full masquerade; establish with the real peer container,
# then the UPDATE / DEREGISTER / re-add REGISTER cycle.
# ---------------------------------------------------------------------------
echo "==> 2: full masquerade (iface dump + NHT answers)"
docker exec -d "$SA" sh -c "zapi-sniff --socket /tmp/zserv-s2.api --log /root/sniff-s2.log --respond-hello --hello-cmd 19 --respond-labelmgr --respond-iface eth0:2:$SA_IP/$SA_PLEN --respond-nht"
sleep 1
docker exec "$SA" sh -c "test -S /tmp/zserv-s2.api" || { echo "sniff s2 socket never appeared" >&2; exit 1; }

echo "==> 2: real EBGP peer (bgpd in $SB, no zebra — pure TCP peer)"
docker exec -i "$SB" sh -c 'cat > /etc/frr/bgpd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname m1-leg2-b
router bgp 65001
 bgp router-id $SB_IP
 neighbor $SA_IP remote-as 65000
 neighbor $SA_IP passive
EOF
docker exec "$SB" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf --log file:/root/bgpd-b.log --log-level debug"
wait_vty "$SB" bgpd

echo "==> 2: bgpd with the peer neighbor + bfd (single-hop, remote-as 65001)"
docker exec -i "$SA" sh -c 'cat > /etc/frr/bgpd.conf' <<EOF
frr version 10.2
frr defaults traditional
hostname m1-leg2-a
router bgp 65000
 bgp router-id $SA_IP
 no bgp ebgp-requires-policy
 neighbor $SB_IP remote-as 65001
 neighbor $SB_IP bfd
EOF
docker exec "$SA" sh -c "/usr/lib/frr/bgpd -d -f /etc/frr/bgpd.conf -z /tmp/zserv-s2.api --log file:/root/bgpd-s2.log --log-level debug"
wait_vty "$SA" bgpd

echo "==> 2: waiting for the EBGP session to establish"
ESTABLISHED=0
for i in $(seq 1 30); do
    if docker exec "$SA" sh -c "vtysh -d bgpd -c 'show bgp neighbor $SB_IP' 2>/dev/null | grep -q 'BGP state = Established'"; then
        ESTABLISHED=1; break
    fi
    sleep 1
done
if [[ "$ESTABLISHED" != 1 ]]; then
    echo "WARN: session never established; capturing anyway" >&2
fi
sleep 5

echo "==> 2: toggle bfd off (the DEREGISTER, 28) and back on (re-add REGISTER)"
docker exec "$SA" sh -c "timeout 20 vtysh -d bgpd -c 'conf t' -c 'router bgp 65000' -c 'no neighbor $SB_IP bfd'" || true
sleep 5
docker exec "$SA" sh -c "timeout 20 vtysh -d bgpd -c 'conf t' -c 'router bgp 65000' -c \"neighbor $SB_IP bfd\"" || true
sleep 5
echo "==> 2: re-fire bfd on the installed session (same addresses -> the UPDATE, 29)"
docker exec "$SA" sh -c "timeout 20 vtysh -d bgpd -c 'conf t' -c 'router bgp 65000' -c \"neighbor $SB_IP bfd\"" || true
sleep 5

echo "==> capture evidence"
docker exec "$SA" sh -c "vtysh -d bgpd -c 'show bgp summary'; vtysh -d bgpd -c 'show bgp neighbor $SB_IP'" \
    > "$QUARANTINE/leg2-bgp-state.txt" 2>&1 || true
docker cp "$SA:/root/sniff-s1.log" "$QUARANTINE/leg1-sniff.log"
docker cp "$SA:/root/sniff-s2.log" "$QUARANTINE/leg2-sniff.log"
docker cp "$SA:/root/bgpd-s1.log" "$QUARANTINE/leg1-bgpd.log" || true
docker cp "$SA:/root/bgpd-s2.log" "$QUARANTINE/leg2-bgpd.log" || true
docker cp "$SB:/root/bgpd-b.log" "$QUARANTINE/leg2-bgpd-peer.log" || true
docker rm -f "$SA" "$SB" >/dev/null

echo "M1: DONE (analyze $QUARANTINE/leg{1,2}-sniff.log)"
