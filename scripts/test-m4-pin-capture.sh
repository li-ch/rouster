#!/usr/bin/env bash
# M4 pin-capture session (S1, 2026-10-10): one container, one resident
# zapi-neigh-probe against a REAL zebra 10.2.2, kernel/zebra mutations
# driven in-window. Captures the wire ground truth for:
#   - ZEBRA_NEIGH_REGISTER (131, source-pinned body afi u16) -> the
#     NEIGH_ADDED (128) / NEIGH_REMOVED (129) pushes it subscribes to
#   - INTERFACE_ADD dump frames with a VRF device + enslaved dummy in
#     place (the link_ifindex field, the vrf device's own frame, and the
#     connect-time VRF_ADD (33) pushes)
#   - REDISTRIBUTE_ROUTE_ADD (31) bodies for a main-table static and a
#     table-5001 static (the TABLEID field policy)
#
# Debug capture tool, not a product smoke: the assertions live in the
# analysis of /quarantine/m4/neigh-probe.log, not in this script. Never
# pulls images; caps as the z5 family; self-cleaning.
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=z4-neigh-probe
IMAGE=frr-testbed:10.2.2
QUARANTINE="${ROUSTER_M4_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-10/quarantine/m4}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

trap 'docker rm -f "$R1" >/dev/null 2>&1 || true' EXIT

perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }
docker rm -f "$R1" >/dev/null 2>&1 || true

echo "==> building zapi-neigh-probe ($MUSL_TARGET, release)"
cargo build --release --target "$MUSL_TARGET" --bin zapi-neigh-probe

echo "==> container + real zebra"
docker run -d --name "$R1" --init \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null
docker cp "target/$MUSL_TARGET/release/zapi-neigh-probe" "$R1:/usr/local/bin/"
docker exec "$R1" sh -c "/usr/lib/frr/zebra -d -A 127.0.0.1 --log file:/root/zebra.log --log-level debug"
for _ in $(seq 1 15); do
    docker exec "$R1" sh -c "test -S /var/run/frr/zserv.api" && break
    sleep 1
done
docker exec "$R1" sh -c "test -S /var/run/frr/zserv.api" || { echo "zebra socket never appeared" >&2; exit 1; }

echo "==> VRF device + enslaved dummy (BEFORE the probe connects)"
docker exec "$R1" sh -c "ip link add vrf-test type vrf table 5001 && ip link set vrf-test up && ip link add dummy0 type dummy && ip link set dummy0 master vrf-test && ip link set dummy0 up && ip addr add 192.0.2.1/24 dev dummy0"

echo "==> mgmtd + staticd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z /var/run/frr/zserv.api --log file:/root/mgmtd.log"
docker exec "$R1" sh -c "/usr/lib/frr/staticd -d -z /var/run/frr/zserv.api --log file:/root/staticd.log"
sleep 1

echo "==> resident probe (25 s window)"
docker exec -d "$R1" sh -c "zapi-neigh-probe --socket /var/run/frr/zserv.api --log /root/neigh-probe.log --secs 25"
sleep 3

echo "==> neighbour mutations: default VRF (eth0) then VRF slave (dummy0)"
docker exec "$R1" sh -c "ip neigh add 192.168.215.99 lladdr 02:00:00:00:00:99 dev eth0 nud permanent"
sleep 2
docker exec "$R1" sh -c "ip neigh replace 192.168.215.99 lladdr 02:00:00:00:00:aa dev eth0 nud permanent"
sleep 1
docker exec "$R1" sh -c "ip neigh del 192.168.215.99 dev eth0"
sleep 1
docker exec "$R1" sh -c "ip neigh add 192.0.2.99 lladdr 02:00:00:00:00:99 dev dummy0 nud permanent"
sleep 2
docker exec "$R1" sh -c "ip neigh del 192.0.2.99 dev dummy0"
sleep 1

echo "==> static routes: main-table blackhole + table-5001 static"
docker exec "$R1" sh -c "vtysh -c 'conf t' -c 'ip route 203.0.113.0/24 blackhole' -c 'ip route 198.51.100.0/24 192.0.2.9 table 5001'" \
    || docker exec "$R1" sh -c "printf '%s\n' 'ip route 203.0.113.0/24 blackhole' 'ip route 198.51.100.0/24 192.0.2.9 table 5001' > /etc/frr/frr.conf && vtysh -b"
sleep 6

docker exec "$R1" sh -c "echo '--- main ---'; ip route show; echo '--- 5001 ---'; ip route show table 5001; echo '--- neigh ---'; ip neigh show; echo '--- eth0 ---'; ip neigh show dev eth0; echo '--- dummy0 ---'; ip neigh show dev dummy0"

echo "==> capturing evidence"
mkdir -p "$QUARANTINE"
docker cp "$R1:/root/neigh-probe.log" "$QUARANTINE/neigh-probe.log"
docker cp "$R1:/root/zebra.log" "$QUARANTINE/zebra.log" || true
docker exec "$R1" sh -c "ip -d link show; ip route show table 5001" > "$QUARANTINE/kernel-state.txt" || true

echo "m4 pin capture: DONE (analyze $QUARANTINE/neigh-probe.log)"
