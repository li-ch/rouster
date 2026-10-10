#!/usr/bin/env bash
# Z5 interop (direction A): a REAL FRR staticd installs its static routes
# through rousterd into the Linux kernel. FRR-zebra is replaced by rousterd;
# nothing else changes on the FRR side.
#
#   /usr/lib/frr/staticd -d -z /var/run/frr/zserv.api      (FRR 10.2.2)
#        | ZAPI v6 over /var/run/frr/zserv.api (0666)
#   rousterd (residential, config: `zapi socket /var/run/frr/zserv.api`)
#        | netlink
#   kernel: 203.0.113.0/24 blackhole + 198.51.100.0/24 via <bridge-gw> (eth0)
#
# Config delivery: this FRR build has no `staticd -f` option and does not
# auto-read /etc/frr/staticd.conf (Z1 deviation 1, pinned doc operational
# finding 4); static route lines reach staticd only through an mgmtd-backed
# vtysh push, so mgmtd runs alongside staticd and `vtysh -b` boot-pushes
# /etc/frr/frr.conf (its transaction commits asynchronously — the poll
# window below absorbs the delay). The routes still travel
# staticd -> ZAPI -> rousterd -> kernel; the ZAPI path is the object under
# test and is never bypassed.
#
# The reachable gateway is the docker bridge's own gateway on eth0,
# discovered at runtime (a dummy0 self-addressed gateway — the pre-M3
# shape — can never confirm a neighbour: dummy devices hold no ARP, so
# the M3 neighbour-liveness gate answers it permanently unresolved and
# staticd correctly withdraws the route; staticd itself warns "Local
# connected address is configured as Gateway IP"). One warm-up ping
# teaches eth0 the gateway's lladdr BEFORE staticd registers it — the
# deployment-with-traffic shape the gate prescribes.
#
# Machine check (script exit 0): BOTH prefixes present in
# `ip route show proto static` (blackhole prefix + gateway prefix via
# the bridge gateway). rousterd, staticd and mgmtd logs are copied to
# the quarantine dir on success AND failure (trap).
#
# Never pulls images. Container caps: NET_ADMIN for the `ip` commands
# (test-phase0.sh precedent) plus NET_RAW + SYS_ADMIN, which FRR's mgmtd
# demands at privs_init (pinned doc operational finding 7; same cap set as
# Z1's oracle run — still a non-privileged container). The host's network is
# never touched. Container name is z5-*, removed by trap.
#
#   scripts/test-z5-frr-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

NAME=z5-interop
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
STATICD_LOG=/tmp/staticd.log
MGMTD_LOG=/tmp/mgmtd.log
# away/<program>/quarantine/z5 sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_Z5_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-08/quarantine/z5}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

capture() {
    mkdir -p "$QUARANTINE"
    docker cp "$NAME:$ROUSTERD_LOG" "$QUARANTINE/rousterd.log" 2>/dev/null || true
    docker cp "$NAME:$STATICD_LOG" "$QUARANTINE/staticd.log" 2>/dev/null || true
    docker cp "$NAME:$MGMTD_LOG" "$QUARANTINE/mgmtd.log" 2>/dev/null || true
    docker exec "$NAME" sh -c 'ip route show proto static; echo ---; ip route show; echo ---; ip neigh show dev eth0' \
        > "$QUARANTINE/routes.txt" 2>&1 || true
    docker exec "$NAME" sh -c "ls -l $ZAPI_SOCK; pidof staticd; pidof rousterd" \
        > "$QUARANTINE/env.txt" 2>&1 || true
}

wait_in_container() {
    local desc="$1" attempts="$2" body="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$NAME" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (waited $((attempts / 2))s)" >&2
    docker exec "$NAME" sh -c "tail -40 $ROUSTERD_LOG; echo ---; tail -40 $STATICD_LOG" >&2 || true
    return 1
}

trap 'capture; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> building rousterd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd

echo "==> starting container $NAME from $IMAGE (no pull)"
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$IMAGE" infinity >/dev/null

echo "==> installing rousterd"
docker cp "target/$MUSL_TARGET/release/rousterd" "$NAME:/usr/local/bin/rousterd"

echo "==> discovering the bridge gateway + confirming its neighbour (M3 gate)"
GW=$(docker exec "$NAME" sh -c "ip route show default" | awk '{for(i=1;i<=NF;i++) if($i=="via") print $(i+1)}' | head -1)
[ -n "$GW" ] || { echo "FAIL: no default route to use as gateway" >&2; exit 1; }
docker exec "$NAME" ping -c1 -W1 "$GW" >/dev/null 2>&1 || true
docker exec "$NAME" sh -c "ip neigh show $GW dev eth0" | grep -q lladdr \
    || { echo "FAIL: gateway $GW has no lladdr neighbour after warm-up ping" >&2; exit 1; }

echo "==> writing /etc/frr/frr.conf"
docker exec "$NAME" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname r1' \
  'ip route 203.0.113.0/24 blackhole' \
  'ip route 198.51.100.0/24 $GW' \
  'line vty' \
  > $FRR_CONF"

echo "==> starting resident rousterd with the zapi socket"
docker exec "$NAME" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
docker exec -d "$NAME" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in_container "rousterd zapi server listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in_container "zapi socket file exists" 10 "test -S $ZAPI_SOCK"

echo "==> starting mgmtd (config delivery) and REAL FRR staticd against rousterd"
# mgmtd is required for any vtysh config transaction in FRR 10.2 (pinned
# doc operational finding 4). No staticd -f option in this build (Z1
# deviation 1): config arrives via vtysh -b below.
docker exec "$NAME" sh -c \
    "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:$MGMTD_LOG --log-level debug"
docker exec "$NAME" sh -c \
    "/usr/lib/frr/staticd -d -z $ZAPI_SOCK --log file:$STATICD_LOG --log-level debug"
wait_in_container "mgmtd daemonized" 20 "pidof mgmtd"
wait_in_container "staticd daemonized" 20 "pidof staticd"
wait_in_container "staticd vty socket up" 30 "test -S /var/run/frr/staticd.vty"

echo "==> boot-pushing /etc/frr/frr.conf into staticd (vtysh -b)"
docker exec "$NAME" vtysh -b

echo "==> waiting for staticd routes to reach the kernel THROUGH rousterd"
wait_in_container "staticd attached (HELLO in rousterd log)" 30 \
    "grep -q 'zapi: session established' $ROUSTERD_LOG"
wait_in_container "both prefixes in kernel (proto static)" 60 \
    "ip route show proto static | grep -q '203.0.113.0/24' && ip route show proto static | grep -q '198.51.100.0/24'"

echo "==> verifying the gateway route goes via $GW"
docker exec "$NAME" sh -c \
    "ip route show proto static | grep '198.51.100.0/24' | grep -q 'via $GW'"

echo "==> final kernel state (proto static)"
docker exec "$NAME" ip route show proto static

echo "z5 FRR interop: PASS"
