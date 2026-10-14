#!/usr/bin/env bash
# S9-a smoke: BAR-SAV end to end — bgpd learns prefixes with known
# AS_PATHs from REAL FRR peers, the draft-ietf-sidrops-bar-sav-10 §4/§8
# derivation turns them into per-interface allowlists, and the
# spoof-differential proves them on the nft backend.
#
# Topology (four docker bridges, one FRR bgpd each; no pulls):
#
#   frr-sub (AS 202) --- 172.26/24 --- frr-cust (AS 201) --- 172.25/24 --- eth1
#   frr-peer (AS 401) ---------------- 172.27/24 -------------------------- eth2 } rouster
#   frr-prov (AS 501) ---------------- 172.28/24 -------------------------- eth3 }
#
#   rouster container: rousterd (zebra) + rouster bgpd (AS 100) + savd.
#   bgpd peers: 172.25.0.3 role customer, 172.27.0.3 role peer,
#   172.28.0.3 role provider (RFC 9234 roles; same snapshot feeds its
#   rpki stanza). Learned routes export to the kernel (proto bgp) so
#   probe replies route back.
#
#   AS 201 originates 198.51.100.0/24; AS 202 (its customer)
#   198.18.100.0/24 — our Adj-RIB-In sees path [201] and [201,202].
#   AS 401 originates 198.19.100.0/24; AS 501 198.19.0.0/24.
#
# Expected derivation (the unit tests' worked topology, one level up):
#   eth1 (customer): cone {201,202} -> Q {198.51.100.0/24,
#                   198.18.100.0/24} (+ the same VRPs = Q1)
#   eth2 (peer):     cone {401}     -> Q {198.19.100.0/24}
#   eth3 (provider): S {198.51.100.0/24, 198.18.100.0/24} (cone-
#                   exclusive: customer-interface routes ROV-Valid,
#                   ASPA-clean, covering ROAs in Du) -> G = loose - S
#                   = {198.19.100.0/24, 198.19.0.0/24}
#
# Frozen readouts:
#   WIRED      three FRR sessions Established; the M3 feed file carries
#              the four wire-order paths; savd derives 2+1+1 allowlist
#              entries (bar-sav provenance in the status rule lines);
#              kernel holds the four proto-bgp routes.
#   MONITOR-DEFAULT every probe passes (0% loss, rp_filter 0/0/0 — the
#              nft backend never touches sysctls) while the kernel
#              counters diverge: eth3 counts the cone prefix as
#              invalid (the loose-uRPF-equivalent permit, the improper
#              permit BAR-SAV exists to remove — recorded), eth2 the
#              peer-spoof.
#   DROP       (SIGHUP + `action drop` + the friction line) the same
#              probes: cone prefixes still pass on eth1 (0% loss, the
#              /25-deep 198.18.100.9 too — Step 7's cone walk) and the
#              provider/peer's own prefixes on their interfaces; the
#              cone prefix arriving on eth3 is 100% dropped (§8 Step 6
#              — the directional win over loose uRPF) and on eth2
#              (§2's cone separation). Dropped packets still count.
#   CLEAN-EXIT SIGTERM removes the table and every run-dir artifact;
#              the blocked probe passes again.
#
#   scripts/test-sav-barsav.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."
export PATH="$HOME/.cargo/bin:$PATH"

ROUSTER=rouster-barsav
CUST=barsav-cust
SUB=barsav-sub
PEER=barsav-peer
PROV=barsav-prov
NET_CUST=barsav-cust-net
NET_SUB=barsav-sub-net
NET_PEER=barsav-peer-net
NET_PROV=barsav-prov-net
ROUSTER_IMAGE="${ROUSTER_BARSAV_IMAGE:-rouster-nft:local}"
FRR_IMAGE="${ROUSTER_BARSAV_FRR_IMAGE:-frr-testbed:10.2.2}"
ZAPI_SOCK=/run/rouster/zserv.api
ROUSTERD_CONF=/etc/rouster.conf
BGPD_CONF=/etc/rouster-bgp.conf
SAVD_CONF=/etc/savd.conf
RPKI_SNAPSHOT=/etc/rouster/rpki.snapshot
FEED=/run/rouster/barsav-adj-rib-in.txt
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/var/log/rouster-bgpd.log
SAVD_LOG=/var/log/savd.log
STATUS_FILE=/run/rouster/savd.status
RULESET_FILE=/run/rouster/sav-nft.ruleset
MARKER_FILE=/run/rouster/sav-nft-applied
PIDFILE=/run/rouster/savd.pid
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_BARSAV_QUARANTINE:-$SCRIPT_DIR/../../away/2026-10-14/quarantine/barsav}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

# The prefixes the FRR peers originate and the probe sources (all doc
# or benchmark ranges; the /32 probe sources bind on lo in the sender).
CUST_NET_PFX=198.51.100.0/24     # AS 201
SUB_NET_PFX=198.18.100.0/24      # AS 202 (customer of 201)
PEER_PFX=198.19.100.0/24         # AS 401
PROV_PFX=198.19.0.0/24           # AS 501

wait_in() { # <container> <desc> <attempts> <body>
    local container="$1" desc="$2" attempts="$3" body="$4"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$container" sh -c "$body" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "FAIL: $desc (waited ${attempts}s, $container)" >&2
    return 1
}

wait_status() { # <desc> <attempts> <egrep-pattern>
    local desc="$1" attempts="$2" pattern="$3"
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$ROUSTER" savd --show 2>/dev/null | grep -Eq "$pattern"; then
            return 0
        fi
        sleep 0.5
    done
    echo "FAIL: $desc (status never matched: $pattern)" >&2
    docker exec "$ROUSTER" savd --show 1>&2 || true
    return 1
}

count_field() { # <ifindex> <field invalid|valid> <action monitor|drop>
    docker exec "$ROUSTER" savd --show 2>/dev/null \
        | grep "^count iba permit #$1 .* $3 " \
        | grep -o " $2=[0-9]*" | head -1 | cut -d= -f2
}

# Loss percentage of one ping run; busybox ping exits nonzero on 100%
# loss — that is the answer, not an error. An EMPTY answer (ping
# failed to even run) must not kill the script under pipefail: the
# substitution degrades to NO-ANSWER and expect_loss treats that as
# 100%.
ping_loss() { # <container> <command...>
    docker exec "$1" sh -c "${*:2}; true" 2>/dev/null \
        | { grep -o '[0-9]*% packet loss' || true; } | head -1 | cut -d% -f1
}

expect_loss() { # <label> <container> <command> <expected %>
    local got
    # ${*:3:$#-3}: the command words only — the trailing expected-% is
    # NOT part of the command.
    got="$(ping_loss "$2" "${*:3:$(( $# - 3 ))}")"
    echo "    $1: loss=${got:-NO-ANSWER}% (want $4%)"
    [ "${got:-100}" = "$4" ]
}

capture() {
    mkdir -p "$QUARANTINE"
    for c in "$CUST" "$SUB" "$PEER" "$PROV"; do
        docker exec "$c" sh -c "cat /tmp/bgp.log 2>/dev/null; echo ---; \
             vtysh -c 'show bgp summary' 2>/dev/null; echo ---; \
             vtysh -c 'show bgp ipv4 unicast' 2>/dev/null" \
            > "$QUARANTINE/$(echo "$c" | sed 's/barsav-//').txt" 2>&1 || true
    done
    docker exec "$ROUSTER" sh -c \
        "cat $FEED 2>/dev/null; echo ---FEED-END; \
         nft list ruleset; echo ---; ip -br addr show; ip route show; echo ---; \
         cat $STATUS_FILE 2>/dev/null; echo ---; \
         sysctl net.ipv4.conf.all.rp_filter \
                net.ipv4.conf.eth1.rp_filter \
                net.ipv4.conf.eth2.rp_filter \
                net.ipv4.conf.eth3.rp_filter" \
        > "$QUARANTINE/state.txt" 2>&1 || true
    docker exec "$ROUSTER" sh -c "cat $SAVD_LOG" > "$QUARANTINE/savd.log" 2>&1 || true
    docker exec "$ROUSTER" sh -c "cat $BGPD_LOG" > "$QUARANTINE/bgpd.log" 2>&1 || true
    docker exec "$ROUSTER" sh -c "cat $ROUSTERD_LOG" > "$QUARANTINE/rousterd.log" 2>&1 || true
    docker exec "$ROUSTER" sh -c "cat $RPKI_SNAPSHOT; echo ---; cat $SAVD_CONF; echo ---; cat $BGPD_CONF" \
        > "$QUARANTINE/configs.txt" 2>&1 || true
}

cleanup() {
    capture
    docker rm -f "$ROUSTER" "$CUST" "$SUB" "$PEER" "$PROV" >/dev/null 2>&1 || true
    docker network rm "$NET_CUST" "$NET_SUB" "$NET_PEER" "$NET_PROV" >/dev/null 2>&1 || true
}

# 15 s docker pre-flight probe (the run-smokes convention).
perl -e 'alarm 15; exec @ARGV' docker run --rm --entrypoint true "$ROUSTER_IMAGE" \
    || { echo "docker pre-flight probe failed/wedged" >&2; exit 1; }

trap cleanup EXIT
docker rm -f "$ROUSTER" "$CUST" "$SUB" "$PEER" "$PROV" >/dev/null 2>&1 || true
docker network rm "$NET_CUST" "$NET_SUB" "$NET_PEER" "$NET_PROV" >/dev/null 2>&1 || true

echo "==> building rousterd + bgpd + savd ($MUSL_TARGET, release)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bgpd
cargo build --release --target "$MUSL_TARGET" -p sav --bin savd

echo "==> four bridge networks (no pull)"
docker network create --subnet 172.25.0.0/24 "$NET_CUST" >/dev/null
docker network create --subnet 172.26.0.0/24 "$NET_SUB" >/dev/null
docker network create --subnet 172.27.0.0/24 "$NET_PEER" >/dev/null
docker network create --subnet 172.28.0.0/24 "$NET_PROV" >/dev/null

frr_container() { # <name> <net> <ip>
    docker run -d --name "$1" --net "$2" --ip "$3" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        --entrypoint sleep "$FRR_IMAGE" infinity >/dev/null
}

echo "==> starting the FRR peers (AS 201 + its customer 202, peer 401, provider 501)"
frr_container "$CUST" "$NET_CUST" 172.25.0.3
docker network connect --ip 172.26.0.2 "$NET_SUB" "$CUST"
frr_container "$SUB" "$NET_SUB" 172.26.0.3
frr_container "$PEER" "$NET_PEER" 172.27.0.3
frr_container "$PROV" "$NET_PROV" 172.28.0.3

frr_bgp() { # <container> <asn> <extra router lines...>
    local container="$1" asn="$2"
    shift 2
    {
        echo "frr version 10.2"
        echo "frr defaults traditional"
        echo "hostname $container"
        echo "router bgp $asn"
        # Standalone bgpd has no zebra view to pick an identifier
        # from, and rejects sessions while its id is 0.0.0.0 — pin it.
        echo " bgp router-id $ROUTER_ID"
        echo " no bgp ebgp-requires-policy"
        echo " no bgp network import-check"
        for line in "$@"; do echo "$line"; done
        echo "line vty"
    } > /tmp/$container.conf
    docker cp "/tmp/$container.conf" "$container:/tmp/bgpd.conf"
    docker exec "$container" sh -c \
        "/usr/lib/frr/bgpd -d -f /tmp/bgpd.conf --log file:/tmp/bgp.log --log-level info"
}

ROUTER_ID=172.25.0.3 frr_bgp "$CUST" 201 \
    " neighbor 172.25.0.2 remote-as 100" \
    " neighbor 172.25.0.2 timers 3 9" \
    " neighbor 172.26.0.3 remote-as 202" \
    " neighbor 172.26.0.3 timers 3 9" \
    " address-family ipv4 unicast" \
    "  network $CUST_NET_PFX" \
    " exit-address-family"
ROUTER_ID=172.26.0.3 frr_bgp "$SUB" 202 \
    " neighbor 172.26.0.2 remote-as 201" \
    " neighbor 172.26.0.2 timers 3 9" \
    " address-family ipv4 unicast" \
    "  network $SUB_NET_PFX" \
    " exit-address-family"
ROUTER_ID=172.27.0.3 frr_bgp "$PEER" 401 \
    " neighbor 172.27.0.2 remote-as 100" \
    " neighbor 172.27.0.2 timers 3 9" \
    " address-family ipv4 unicast" \
    "  network $PEER_PFX" \
    " exit-address-family"
ROUTER_ID=172.28.0.3 frr_bgp "$PROV" 501 \
    " neighbor 172.28.0.2 remote-as 100" \
    " neighbor 172.28.0.2 timers 3 9" \
    " address-family ipv4 unicast" \
    "  network $PROV_PFX" \
    " exit-address-family"

echo "==> rouster container on the three BAR-SAV bridges"
docker run -d --name "$ROUSTER" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --entrypoint sleep "$ROUSTER_IMAGE" infinity >/dev/null
docker network connect --ip 172.25.0.2 "$NET_CUST" "$ROUSTER"
docker network connect --ip 172.27.0.2 "$NET_PEER" "$ROUSTER"
docker network connect --ip 172.28.0.2 "$NET_PROV" "$ROUSTER"
docker cp "target/$MUSL_TARGET/release/rousterd" "$ROUSTER:/usr/local/bin/rousterd"
docker cp "target/$MUSL_TARGET/release/bgpd" "$ROUSTER:/usr/local/bin/rouster-bgpd"
docker cp "target/$MUSL_TARGET/release/savd" "$ROUSTER:/usr/local/bin/savd"
docker exec "$ROUSTER" mkdir -p /etc/rouster /var/log /run/rouster

# Kernel uRPF must stay OFF the whole run: the nft backend never
# touches sysctls, and a nonzero rp_filter on eth3 would drop the
# monitor leg's directionality probe before the SAV table sees it.
# The mount is read-only in this image class (the test-savd-nft
# lesson) — zero what is zeroable, then ASSERT the values: a nonzero
# rp_filter would shadow the whole smoke.
for i in eth1 eth2 eth3; do
    [ "$(docker exec "$ROUSTER" cat /proc/sys/net/ipv4/conf/$i/rp_filter)" = 0 ] \
        || { echo "FAIL: $i rp_filter is not 0 (kernel uRPF would shadow the test)" >&2; exit 1; }
done

CUST_IF="$(docker exec "$ROUSTER" cat /sys/class/net/eth1/ifindex)"
PEER_IF="$(docker exec "$ROUSTER" cat /sys/class/net/eth2/ifindex)"
PROV_IF="$(docker exec "$ROUSTER" cat /sys/class/net/eth3/ifindex)"
echo "    eth1(customer)=$CUST_IF  eth2(peer)=$PEER_IF  eth3(provider)=$PROV_IF"

# The probe sources: /32s on lo in the SENDING container (bindable but
# never routed/announced by it — 198.51.100.9 IS announced by AS 201,
# the legitimate owner; the point is which INTERFACE it arrives on).
docker exec "$CUST" ip addr add 198.51.100.9/32 dev lo
docker exec "$CUST" ip addr add 198.18.100.9/32 dev lo
docker exec "$PEER" ip addr add 198.19.100.9/32 dev lo
docker exec "$PROV" ip addr add 198.19.0.9/32 dev lo

echo "==> configs: rpki snapshot shared by bgpd and savd"
docker exec "$ROUSTER" sh -c "printf '%s\n' \
  'vrp $CUST_NET_PFX max 24 as 201' \
  'vrp $SUB_NET_PFX max 24 as 202' \
  'vrp $PEER_PFX max 24 as 401' \
  'vrp $PROV_PFX max 24 as 501' \
  'aspa 202 provider 201' \
  > $RPKI_SNAPSHOT"
docker exec "$ROUSTER" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  > $ROUSTERD_CONF"
docker exec "$ROUSTER" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router bgp 100' \
  ' bgp router-id 172.25.0.2' \
  ' neighbor 172.25.0.3 remote-as 201' \
  ' neighbor 172.25.0.3 role customer' \
  ' neighbor 172.25.0.3 timers 3 9' \
  ' neighbor 172.27.0.3 remote-as 401' \
  ' neighbor 172.27.0.3 role peer' \
  ' neighbor 172.27.0.3 timers 3 9' \
  ' neighbor 172.28.0.3 remote-as 501' \
  ' neighbor 172.28.0.3 role provider' \
  ' neighbor 172.28.0.3 timers 3 9' \
  'rpki' \
  ' vrp-file $RPKI_SNAPSHOT' \
  'barsav' \
  ' feed $FEED' \
  > $BGPD_CONF"
docker exec "$ROUSTER" sh -c "printf '%s\n' \
  'backend nft' \
  'poll 1' \
  'barsav feed $FEED' \
  'barsav vrp-file $RPKI_SNAPSHOT' \
  'barsav local-as 100' \
  'interface eth1' \
  ' mode barsav' \
  ' role customer' \
  ' remote-as 201' \
  'interface eth2' \
  ' mode barsav' \
  ' role peer' \
  ' remote-as 401' \
  'interface eth3' \
  ' mode barsav' \
  ' role provider' \
  ' remote-as 501' \
  > $SAVD_CONF"

echo "==> resident rousterd, then rouster bgpd (AS 100)"
docker exec -d "$ROUSTER" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
wait_in "$ROUSTER" "rousterd zapi server up" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
# Seed ARP toward each peer (the NHT gate wants lladdr entries).
for ip in 172.25.0.3 172.27.0.3 172.28.0.3; do
    docker exec "$ROUSTER" ping -c1 -W1 "$ip" >/dev/null 2>&1 || true
done
docker exec -d "$ROUSTER" sh -c "rouster-bgpd --config $BGPD_CONF > $BGPD_LOG 2>&1"
wait_in "$ROUSTER" "our bgpd is up" 10 "pidof rouster-bgpd"

echo "==> WIRED: three FRR sessions Established, four paths in the feed"
wait_in "$ROUSTER" "customer session Established" 60 \
    "grep 'session Established' $BGPD_LOG | grep -q 172.25.0.3"
wait_in "$ROUSTER" "peer session Established" 60 \
    "grep 'session Established' $BGPD_LOG | grep -q 172.27.0.3"
wait_in "$ROUSTER" "provider session Established" 60 \
    "grep 'session Established' $BGPD_LOG | grep -q 172.28.0.3"
# FRR's summary shows a prefix count, not the word — the neighbor
# detail carries the state line (the interop-smoke form).
wait_in "$CUST" "FRR cust sees Established" 60 \
    "timeout 5 vtysh -c 'show bgp neighbor 172.25.0.2' | grep -q 'BGP state = Established'"
wait_in "$ROUSTER" "feed carries the customer path" 30 \
    "grep -q '^$CUST_NET_PFX peer 172.25.0.3 path 201$' $FEED"
wait_in "$ROUSTER" "feed carries the deep-cone path" 30 \
    "grep -q '^$SUB_NET_PFX peer 172.25.0.3 path 201 202$' $FEED"
wait_in "$ROUSTER" "feed carries the peer path" 30 \
    "grep -q '^$PEER_PFX peer 172.27.0.3 path 401$' $FEED"
wait_in "$ROUSTER" "feed carries the provider path" 30 \
    "grep -q '^$PROV_PFX peer 172.28.0.3 path 501$' $FEED"
# The image's busybox ip cannot filter by proto NAME (186 bgp is
# unnamed there) — the plain table is the kernel truth the probes'
# replies depend on.
for pfx in "$CUST_NET_PFX" "$SUB_NET_PFX" "$PEER_PFX" "$PROV_PFX"; do
    wait_in "$ROUSTER" "kernel route $pfx" 30 \
        "ip route show | grep -q '$pfx'"
done
echo "    WIRED: 3x Established, feed has the four wire-order paths, 4x proto-bgp routes"

echo "==> savd (backend nft, monitor by default)"
docker exec -d "$ROUSTER" sh -c "savd --config $SAVD_CONF --zapi-socket $ZAPI_SOCK > $SAVD_LOG 2>&1"
wait_in "$ROUSTER" "savd synced its rib view" 30 "grep -q 'rib view synced' $SAVD_LOG"
wait_in "$ROUSTER" "customer allowlist derived" 30 \
    "grep -q 'barsav allowlist derived' $SAVD_LOG"
wait_in "$ROUSTER" "provider allowlist derived" 30 \
    "grep -q 'barsav provider allowlist derived' $SAVD_LOG"
wait_in "$ROUSTER" "rule set installed" 30 "grep -q 'rule set installed' $SAVD_LOG"
[ "$(docker exec "$ROUSTER" sh -c "grep -c 'savd: rule rule=' $SAVD_LOG")" = 3 ]
# The derived content, straight from the startup log: the customer
# allowlist carries the cone (both prefixes), the peer's its own, the
# provider's G excludes the cone.
docker exec "$ROUSTER" sh -c "grep 'savd: rule rule=' $SAVD_LOG" | grep "198.51.100.0/24"
docker exec "$ROUSTER" sh -c "grep 'savd: rule rule=' $SAVD_LOG" | grep "198.18.100.0/24"
docker exec "$ROUSTER" sh -c "grep 'savd: rule ' $SAVD_LOG" >"$QUARANTINE/rules-monitor.txt" || true
docker exec "$ROUSTER" sh -c \
    "grep 'rule=allow if#$PROV_IF' $SAVD_LOG" | grep -q "198.19.0.0/24"
if docker exec "$ROUSTER" sh -c "grep 'rule=allow if#$PROV_IF' $SAVD_LOG" | grep -q "198.51.100.0/24"; then
    echo "FAIL: cone prefix leaked into the provider allowlist (S subtraction broken)" >&2
    exit 1
fi
wait_status "status shows 3 bar-sav rules" 20 '^installed 3 rules'
docker exec "$ROUSTER" savd --show 2>/dev/null | grep -q 'from bar-sav'
wait_in "$ROUSTER" "nft table live" 20 "nft list table inet rouster_sav | grep -q prerouting"
echo "    derived: customer(cone 2) + peer(1) + provider(G 2, S excluded); installed 3 rules"

# Probe matrix (sender, source, target): the arrival interface is the
# target's bridge.
LEGIT_CUST='ping -c3 -W1 -I 198.51.100.9 172.25.0.2'
LEGIT_DEEP='ping -c3 -W1 -I 198.18.100.9 172.25.0.2'
SPOOF_PROV='ping -c3 -W1 -I 198.51.100.9 172.28.0.2'
LEGIT_PROV='ping -c3 -W1 -I 198.19.0.9 172.28.0.2'
LEGIT_PEER='ping -c3 -W1 -I 198.19.100.9 172.27.0.2'
SPOOF_PEER='ping -c3 -W1 -I 198.51.100.9 172.27.0.2'

echo "==> MONITOR-DEFAULT: everything passes, kernel counters diverge"
expect_loss "cone prefix on customer iface (legit)" "$CUST" "$LEGIT_CUST" 0
expect_loss "deep-cone prefix on customer iface (legit)" "$CUST" "$LEGIT_DEEP" 0
expect_loss "cone prefix on provider iface (the §8 probe)" "$CUST" "$SPOOF_PROV" 0
expect_loss "provider's own prefix on provider iface (legit)" "$PROV" "$LEGIT_PROV" 0
expect_loss "peer's own prefix on peer iface (legit)" "$PEER" "$LEGIT_PEER" 0
expect_loss "cone prefix on peer iface (spoof)" "$CUST" "$SPOOF_PEER" 0
wait_status "provider iface counted the cone prefix invalid" 20 \
    "count iba permit #$PROV_IF .* monitor .* invalid=[1-9][0-9]*"
wait_status "peer iface counted the cone prefix invalid" 20 \
    "count iba permit #$PEER_IF .* monitor .* invalid=[1-9][0-9]*"
wait_status "customer iface counted its legits valid" 20 \
    "count iba permit #$CUST_IF .* monitor .* valid=[1-9][0-9]*"
MON_INV="$(count_field "$PROV_IF" invalid monitor)"
echo "    MONITOR: 0% loss everywhere, eth3 invalid=$MON_INV (the loose-equivalent permit, recorded)"
{
    echo "uRPF baseline comparison (recorded $(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo "kernel uRPF: rp_filter 0 on all interfaces the whole run (nft backend"
    echo "  never touches sysctls) — no legacy uRPF shadows these readouts."
    echo "loose-uRPF equivalence: monitor leg passes 198.51.100.9 on eth3 with"
    echo "  0% loss (a route exists — exactly loose uRPF's permit), invalid=$MON_INV"
    echo "  counted. BAR-SAV's §8 Step 6 subtracts exactly this improper permit:"
    echo "  the drop leg below blocks the same probe while the customer leg keeps"
    echo "  passing it — directionality loose uRPF cannot express."
} > "$QUARANTINE/urpf-baseline.txt"
for i in eth1 eth2 eth3; do
    [ "$(docker exec "$ROUSTER" cat /proc/sys/net/ipv4/conf/$i/rp_filter)" = 0 ]
done

echo "==> [DROP] SIGHUP with action drop + the friction line"
docker exec "$ROUSTER" sh -c "printf '%s\n' \
  'backend nft' \
  'poll 1' \
  'barsav feed $FEED' \
  'barsav vrp-file $RPKI_SNAPSHOT' \
  'barsav local-as 100' \
  'action drop' \
  'i-understand-drop-mode yes' \
  'interface eth1' \
  ' mode barsav' \
  ' role customer' \
  ' remote-as 201' \
  'interface eth2' \
  ' mode barsav' \
  ' role peer' \
  ' remote-as 401' \
  'interface eth3' \
  ' mode barsav' \
  ' role provider' \
  ' remote-as 501' \
  > $SAVD_CONF"
docker exec "$ROUSTER" sh -c 'kill -HUP "$(pidof savd)"'
wait_in "$ROUSTER" "reload swapped in the drop rules" 30 \
    "grep 'rule added' $SAVD_LOG | grep -q 'drop'"
wait_in "$ROUSTER" "drop verdicts live in the kernel table" 20 \
    "nft list table inet rouster_sav | grep -qw drop"
docker exec "$ROUSTER" nft list table inet rouster_sav >"$QUARANTINE/rules-drop.txt" || true

echo "==> DROP differential"
expect_loss "cone prefix on customer iface STILL passes" "$CUST" "$LEGIT_CUST" 0
expect_loss "deep-cone (AS 202) prefix passes (§4 Step 7 cone walk)" "$CUST" "$LEGIT_DEEP" 0
expect_loss "cone prefix on provider iface BLOCKED (§8 Step 6)" "$CUST" "$SPOOF_PROV" 100
expect_loss "provider's own prefix still passes" "$PROV" "$LEGIT_PROV" 0
expect_loss "peer's own prefix still passes" "$PEER" "$LEGIT_PEER" 0
expect_loss "cone prefix on peer iface BLOCKED (§2 cone separation)" "$CUST" "$SPOOF_PEER" 100
wait_status "dropped cone packets still counted on eth3" 20 \
    "count iba permit #$PROV_IF .* drop .* invalid=[1-9][0-9]*"
DROP_INV="$(count_field "$PROV_IF" invalid drop)"
echo "    DROP: improper block 0 (legits pass), directional block 100%, eth3 invalid=$DROP_INV (deny-rule counter)"
docker exec "$ROUSTER" savd --show >"$QUARANTINE/status-drop.txt" 2>/dev/null

echo "==> [CLEAN-EXIT] SIGTERM removes every installed rule"
docker exec "$ROUSTER" sh -c 'kill -TERM "$(pidof savd)"'
wait_in "$ROUSTER" "savd exited" 20 '! pidof savd >/dev/null'
if docker exec "$ROUSTER" nft list table inet rouster_sav >/dev/null 2>&1; then
    echo "table still present after clear" >&2; exit 1
fi
docker exec "$ROUSTER" sh -c \
    "[ ! -e $RULESET_FILE ] && [ ! -e $MARKER_FILE ] \
     && [ ! -e $STATUS_FILE ] && [ ! -e $PIDFILE ]"
expect_loss "post-clear the §8 probe passes again" "$CUST" "$SPOOF_PROV" 0
echo "    CLEAN-EXIT: table/ruleset/marker/status/pidfile gone, probe passes again"

echo "barsav smoke test: PASS"
