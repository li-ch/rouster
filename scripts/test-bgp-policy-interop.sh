#!/usr/bin/env bash
# BGP policy/RPKI interop (W2-d, M4): the P2-b two-container topology
# with the typed policy engine and ROV live in the decision path.
#
#   bgp-pol-r1 (FRR side):   rousterd (zebra) + mgmtd + REAL bgpd 10.2.2
#   bgp-pol-r2 (ours):       rousterd (zebra) + rouster bgpd
#
#   eBGP AS 65001 (FRR) <-> AS 65000 (ours), hold 30 / keepalive 10.
#
#   FRR networks: 198.51.100.0/24 (VRP says AS 65001 -> Valid)
#                 203.0.113.0/24 (VRP says AS 64512 -> Invalid)
#   Our networks: 192.0.2.0/24    (export route-map permits it)
#                 198.18.0.0/24   (export route-map denies it)
#
# Machine checks (script exit 0):
#   - PEER-BOTH: FRR `show bgp neighbor` Established AND our bgpd
#     logged "session Established".
#   - RPKI-INVALID-REJECTED: our bgpd logged "route rejected, RPKI
#     Invalid" for 203.0.113.0/24; r2's kernel has NO proto-bgp route
#     for it and r2's rousterd never logged a route add for it.
#   - RPKI-VALID-INSTALLED: 198.51.100.0/24 in r2's kernel proto bgp
#     through a logged rousterd route add.
#   - EXPORT-FILTER: FRR's `show bgp ipv4 unicast` holds 192.0.2.0/24
#     and NOT 198.18.0.0/24 (the Adj-RIB-Out gate).
#   - TEARDOWN: SIGTERM our bgpd -> Cease observed on the FRR side.
#
# Never pulls images (frr-testbed:10.2.2 cached); caps as the z5
# family; self-cleaning; quarantine (absolute path) under
# away/2026-10-11/weekend/quarantine/bgp-policy/ on success AND
# failure.
#
#   scripts/test-bgp-policy-interop.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

R1=bgp-pol-r1
R2=bgp-pol-r2
IMAGE=frr-testbed:10.2.2
ZAPI_SOCK=/var/run/frr/zserv.api
FRR_CONF=/etc/frr/frr.conf
ROUSTERD_CONF=/etc/rouster.conf
ROUSTERD_LOG=/var/log/rousterd.log
BGPD_LOG=/tmp/bgpd.log         # FRR bgpd on r1
OUR_BGPD_LOG=/var/log/rouster-bgpd.log
VRP_FILE=/etc/rouster-vrps.conf
VALID_NET=198.51.100.0/24      # FRR-originated, VRP -> Valid
INVALID_NET=203.0.113.0/24     # FRR-originated, VRP -> Invalid
PERMIT_NET=192.0.2.0/24        # ours, export-filtered IN
BLOCK_NET=198.18.0.0/24        # ours, export-filtered OUT
QUARANTINE="${ROUSTER_BGP_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/weekend/quarantine/bgp-policy}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

bridge_ip() {
    docker exec "$1" sh -c "ip -4 addr show dev eth0" | sed -n 's/.*inet \([0-9.]*\)\/.*/\1/p' | head -1
}

capture() {
    mkdir -p "$QUARANTINE/r1" "$QUARANTINE/r2"
    for side in r1 r2; do
        name="$R1"; [ "$side" = r2 ] && name="$R2"
        docker cp "$name:$ROUSTERD_LOG" "$QUARANTINE/$side/rousterd.log" 2>/dev/null || true
        docker exec "$name" sh -c "ip route show; echo ---; ip route show proto bgp" \
            > "$QUARANTINE/$side/routes.txt" 2>&1 || true
    done
    docker cp "$R1:$BGPD_LOG" "$QUARANTINE/r1/frr-bgpd.log" 2>/dev/null || true
    docker cp "$R1:$FRR_CONF" "$QUARANTINE/r1/frr.conf" 2>/dev/null || true
    docker exec "$R1" sh -c "vtysh -c 'show bgp summary'; echo ---; vtysh -c 'show bgp ipv4 unicast'; echo ---; vtysh -c 'show bgp neighbor'" \
        > "$QUARANTINE/r1/bgp.txt" 2>&1 || true
    docker cp "$R2:$OUR_BGPD_LOG" "$QUARANTINE/r2/rouster-bgpd.log" 2>/dev/null || true
    docker exec "$R2" sh -c "cat /etc/rouster-bgp.conf; echo ---; cat $VRP_FILE" \
        > "$QUARANTINE/r2/rouster-bgp.conf" 2>&1 || true
}

fail() {
    echo "FAIL: $*" >&2
    for entry in "$R1:$ROUSTERD_LOG rousterd-r1" "$R2:$ROUSTERD_LOG rousterd-r2" "$R2:$OUR_BGPD_LOG our-bgpd"; do
        name="${entry%%:*}"; what="${entry#*:}"; log="${what%% *}"
        echo "--- $what tail ---" >&2
        docker exec "$name" sh -c "tail -25 $log" >&2 || true
    done
    echo "--- FRR bgpd tail ---" >&2
    docker exec "$R1" sh -c "tail -20 $BGPD_LOG" >&2 || true
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

echo "==> building rousterd + bgpd ($MUSL_TARGET, release)"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" --bin rousterd --bin bgpd

echo "==> starting containers from $IMAGE (no pull, docker bridge)"
for name in "$R1" "$R2"; do
    PUBLISH=""
    # r2 publishes its bgpd listener for the host-side crafted peer
    # of the RFC 7606 leg (N5 M4).
    [ "$name" = "$R2" ] && PUBLISH="-p 127.0.0.1:11790:179"
    docker run -d --name "$name" \
        --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
        $PUBLISH \
        --entrypoint sleep "$IMAGE" infinity >/dev/null
    docker cp "target/$MUSL_TARGET/release/rousterd" "$name:/usr/local/bin/rousterd"
    docker cp "target/$MUSL_TARGET/release/bgpd" "$name:/usr/local/bin/rouster-bgpd"
    docker exec "$name" sh -c "echo '186 bgp' >> /etc/iproute2/rt_protos"
done

R1_IP=$(bridge_ip "$R1")
R2_IP=$(bridge_ip "$R2")
# The bridge gateway: the source address the host-side crafted peer's
# connection carries after the publish-path NAT.
GW_IP=$(docker exec "$R2" sh -c "ip route show default" | awk "{print \$3}")
echo "==> bridge addresses: frr-r1=$R1_IP rouster-r2=$R2_IP gw=$GW_IP"

echo "==> resident rousterd (zebra) in both containers"
for name in "$R1" "$R2"; do
    docker exec "$name" sh -c "printf '%s\n' 'zapi socket $ZAPI_SOCK' > $ROUSTERD_CONF"
    docker exec -d "$name" sh -c "rousterd --config $ROUSTERD_CONF > $ROUSTERD_LOG 2>&1"
done
wait_in "$R1" "r1 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"
wait_in "$R2" "r2 rousterd listening" 30 "grep -q 'zapi: listening' $ROUSTERD_LOG"

echo "==> r1: mgmtd + REAL FRR bgpd against rousterd"
docker exec "$R1" sh -c "/usr/lib/frr/mgmtd -d -z $ZAPI_SOCK --log file:/tmp/mgmtd.log --log-level debug"
docker exec "$R1" sh -c "/usr/lib/frr/bgpd -d -z $ZAPI_SOCK --log file:$BGPD_LOG --log-level debug"
wait_in "$R1" "r1 bgpd vty socket" 30 "test -S /var/run/frr/bgpd.vty"

echo "==> r2: the VRP fixture (198.51.100.0/24 -> 65001 Valid; 203.0.113.0/24 -> 64512 Invalid)"
docker exec "$R2" sh -c "printf '%s\n' \
  '# W2-d interop fixture' \
  'vrp $VALID_NET max 24 as 65001' \
  'vrp $INVALID_NET max 24 as 64512' \
  > $VRP_FILE"

echo "==> r2: rouster bgpd with rpki + export filter"
docker exec "$R2" sh -c "printf '%s\n' \
  'zapi socket $ZAPI_SOCK' \
  'router bgp 65000' \
  ' bgp router-id $R2_IP' \
  ' neighbor $R1_IP remote-as 65001' \
  ' neighbor $GW_IP remote-as 65042' \
  ' neighbor $GW_IP passive' \
  ' hold-time 30' \
  ' network $PERMIT_NET' \
  ' network $BLOCK_NET' \
  ' export OUT' \
  'rpki' \
  ' vrp-file $VRP_FILE' \
  'route-map OUT permit 10' \
  ' match ip address prefix-list PERMIT' \
  'ip prefix-list PERMIT seq 5 permit $PERMIT_NET' \
  > /etc/rouster-bgp.conf"
docker exec "$R2" sh -c "cat /etc/rouster-bgp.conf"

echo "==> FRR side config (vtysh -b)"
docker exec "$R1" sh -c "printf '%s\n' \
  'frr version 10.2' \
  'frr defaults traditional' \
  'hostname frr-r1' \
  'router bgp 65001' \
  ' no bgp network import-check' \
  ' no bgp ebgp-requires-policy' \
  ' neighbor $R2_IP remote-as 65000' \
  ' neighbor $R2_IP timers 10 30' \
  ' address-family ipv4 unicast' \
  '  network $VALID_NET' \
  '  network $INVALID_NET' \
  ' exit-address-family' \
  'line vty' \
  > $FRR_CONF"

# The zebra-view race: retry the push until the neighbor exists (the
# P2-b pinned fact — vtysh -b too early silently drops the stanza).
APPLIED=0
for _ in $(seq 1 10); do
    docker exec "$R1" vtysh -b >/dev/null 2>&1 || true
    sleep 2
    if docker exec "$R1" sh -c "vtysh -c 'show bgp summary' 2>/dev/null | grep -q '$R2_IP'"; then
        APPLIED=1
        break
    fi
done
[ "$APPLIED" = 1 ] || fail "FRR neighbor config never applied (zebra-view race)"
wait_in "$R1" "FRR bgpd bound :179" 20 "grep -qi '00B3' /proc/net/tcp"

echo "==> seeding both sides' ARP (the NHT gate needs lladdr entries)"
docker exec "$R1" ping -c1 -W1 "$R2_IP" >/dev/null 2>&1 || true
docker exec "$R2" ping -c1 -W1 "$R1_IP" >/dev/null 2>&1 || true
docker exec "$R1" sh -c "ip neigh show $R2_IP dev eth0" | grep -q lladdr \
    || fail "r1 has no lladdr neighbour for $R2_IP"
docker exec "$R2" sh -c "ip neigh show $R1_IP dev eth0" | grep -q lladdr \
    || fail "r2 has no lladdr neighbour for $R1_IP"

echo "==> starting rouster bgpd on r2"
docker exec -d "$R2" sh -c "rouster-bgpd --config /etc/rouster-bgp.conf > $OUR_BGPD_LOG 2>&1"
wait_in "$R2" "our bgpd is up" 10 "pidof rouster-bgpd"

echo "==> PEER-BOTH: waiting for Established on both sides"
wait_in "$R1" "FRR sees Established" 60 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'BGP state = Established'"
wait_in "$R2" "our bgpd logged Established" 60 \
    "grep -q 'session Established' $OUR_BGPD_LOG"

echo "==> RPKI-INVALID-REJECTED: $INVALID_NET never installed"
wait_in "$R2" "our bgpd logged the RPKI rejection" 30 \
    "grep 'rejected, RPKI Invalid' $OUR_BGPD_LOG | grep -q '$INVALID_NET'"
sleep 3
docker exec "$R2" sh -c "ip route show proto bgp" | grep -q "$INVALID_NET" \
    && fail "$INVALID_NET leaked into the kernel despite ROV"
docker exec "$R2" sh -c "grep 'zapi: route add' $ROUSTERD_LOG" | grep -q "$INVALID_NET" \
    && fail "rousterd programmed $INVALID_NET despite ROV"

echo "==> RPKI-VALID-INSTALLED: $VALID_NET in kernel via rousterd"
wait_in "$R2" "r2 rousterd logged the BGP route add" 30 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$VALID_NET'"
wait_in "$R2" "$VALID_NET in r2 kernel proto bgp" 30 \
    "ip route show proto bgp | grep -q '$VALID_NET'"

echo "==> EXPORT-FILTER: FRR receives only $PERMIT_NET"
wait_in "$R1" "FRR has $PERMIT_NET in show bgp" 30 \
    "vtysh -c 'show bgp ipv4 unicast $PERMIT_NET' | grep -q '$PERMIT_NET'"
docker exec "$R1" sh -c "vtysh -c 'show bgp ipv4 unicast $BLOCK_NET'" | grep -q "$BLOCK_NET" \
    && fail "$BLOCK_NET reached FRR despite the export filter"
docker exec "$R1" sh -c "vtysh -c 'show bgp ipv4 unicast'" | grep -q "$BLOCK_NET" \
    && fail "$BLOCK_NET appears anywhere in FRR's table"

echo "==> RFC7606: malformed optional attribute from a crafted peer —"
echo "    route discarded, session survives (treat-as-withdraw)"
CRAFT_NET_A=198.18.7.0/24   # announced good, then re-announced malformed
CRAFT_NET_B=198.18.8.0/24   # announced after the malformed UPDATE
# The fixture lands in quarantine BEFORE the run's own mkdir (line
# ~326) — on a fresh checkout the dir does not exist yet and the
# heredoc dies with "No such file or directory" (CI run 38647649951).
mkdir -p "$QUARANTINE"
cat > "$QUARANTINE/crafted-peer.pl" <<'PERL'
#!/usr/bin/perl
# A crafted BGP peer (N5 M4): establishes with rouster bgpd, announces
# a good route, re-announces the SAME prefix with a malformed
# COMMUNITIES attribute (RFC 7606 §7 -> treat-as-withdraw: the route is
# withdrawn), then announces a second good route — the session must
# have survived the malformed UPDATE throughout.
use strict;
use warnings;
use IO::Socket::INET;
my ($port, $nexthop) = @ARGV;
die "usage: crafted-peer.pl <port> <nexthop-ip>\n" unless $nexthop;
my $sock = IO::Socket::INET->new(PeerAddr => "127.0.0.1",
                                 PeerPort => $port, Proto => "tcp")
    or die "connect: $!";
$sock->autoflush(1);

sub frame { my ($type, $body) = @_;
    return "\xff" x 16 . pack("nC", 19 + length($body), $type) . $body; }
sub read_frame {
    my $hdr = "";
    while (length($hdr) < 19) {
        my $n = sysread($sock, my $b, 19 - length($hdr));
        die "eof mid-header" unless $n;
        $hdr .= $b;
    }
    my ($len, $type) = unpack("x16nC", $hdr);
    my $body = "";
    while (length($body) < $len - 19) {
        my $n = sysread($sock, my $b, $len - 19 - length($body));
        die "eof mid-body" unless $n;
        $body .= $b;
    }
    return ($type, $body);
}
# OPEN: BGP-4, AS 65042, hold 90, BGP-id 10.42.0.1, advertising the
# 4-octet AS capability (so the UPDATEs' 4-octet AS_PATH decodes).
my $caps     = pack("CC", 65, 4) . pack("N", 65042);
my $params   = pack("CC a*", 2, length($caps), $caps);
my $openbody = pack("Cnn a4 C a*", 4, 65042, 90,
                    pack("C4", 10, 42, 0, 1), length($params), $params);
syswrite($sock, frame(1, $openbody));
while (1) { my ($t) = read_frame(); last if $t == 1; }
syswrite($sock, frame(4, ""));    # KEEPALIVE -> Established
while (1) { my ($t) = read_frame(); last if $t == 4; }

my $attrs =
    "\x40\x01\x01\x00"                      # ORIGIN IGP
  . "\x40\x02\x06\x02\x01\x00\x00\xfe\x12" # AS_PATH 65042 (4-octet)
  . "\x40\x03\x04" . join("", map { chr($_) } split(/\./, $nexthop));  # NEXT_HOP
my $nlri_a = "\x18\xc6\x12\x07";            # 198.18.7.0/24
my $nlri_b = "\x18\xc6\x12\x08";            # 198.18.8.0/24
sub update { my ($a, @nlri) = @_;
    return frame(2, pack("n", 0) . pack("n", length($a)) . $a . join("", @nlri)); }

syswrite($sock, update($attrs, $nlri_a));       # good announce
sleep 2;
# The malformed re-announcement: COMMUNITIES length 3 (not a non-zero
# multiple of 4) — RFC 7606 §7 says treat-as-withdraw.
syswrite($sock, update($attrs . "\xc0\x08\x03\x01\x02\x03", $nlri_a));
sleep 2;
syswrite($sock, update($attrs, $nlri_b));       # proves the session lives
sleep 2;
# Hold the session open while the script's checks read the kernel
# (KEEPALIVEs keep the 30 s hold timer far away).
for my $i (1 .. 12) {
    syswrite($sock, frame(4, ""));
    sleep 2;
}
exit 0;
PERL
mkdir -p "$QUARANTINE"
perl "$QUARANTINE/crafted-peer.pl" 11790 "$R1_IP"

wait_in "$R2" "bgpd logged the treat-as-withdraw" 15 \
    "grep -q 'malformed UPDATE treated as withdrawal (RFC 7606' $OUR_BGPD_LOG"
wait_in "$R2" "the good route arrived after the malformed one" 15 \
    "grep 'UPDATE received' $OUR_BGPD_LOG | grep -q '$CRAFT_NET_B'"
sleep 2
# Route discarded: A was announced good, then the malformed
# re-announcement withdrew it — the kernel no longer holds it; B (the
# post-malformation announce) is there.
docker exec "$R2" sh -c "ip route show proto bgp" | grep -q "$CRAFT_NET_A" \
    && fail "$CRAFT_NET_A still installed despite treat-as-withdraw"
# The zebra-programming proof (fast), then the kernel table (rousterd's
# reconcile programs on a several-second cadence — give it room; the
# crafted peer holds the session ~26 s).
wait_in "$R2" "rousterd programmed $CRAFT_NET_B" 15 \
    "grep 'zapi: route add' $ROUSTERD_LOG | grep -q '$CRAFT_NET_B'"
wait_in "$R2" "$CRAFT_NET_B installed (session survived)" 30 \
    "ip route show proto bgp | grep -q '$CRAFT_NET_B'"
docker exec "$R2" sh -c "grep 'sending NOTIFICATION' $OUR_BGPD_LOG | grep -q '$GW_IP'" \
    && fail "the malformed UPDATE reset the session (RFC 7606 violated)"
docker exec "$R2" sh -c "grep 'connection from unconfigured address' $OUR_BGPD_LOG | grep -q '$GW_IP'" \
    && fail "the crafted peer arrived from an unconfigured address (GW_IP mismatch)"

echo "==> TEARDOWN: SIGTERM our bgpd -> Cease on the FRR side"
docker exec "$R2" sh -c "kill -TERM \$(pidof rouster-bgpd)"
sleep 3
# B-7 (RFC 8538): toward an N-advertising peer our shutdown rides as
# a Hard Reset (Cease/9) — FRR names it "Hard Reset", not
# "Administrative Shutdown"; either proves the deliberate close.
wait_in "$R1" "FRR observed the Cease NOTIFICATION" 20 \
    "vtysh -c 'show bgp neighbor $R2_IP' | grep -q 'Notification received (Cease/'"
wait_in "$R2" "our bgpd exited" 15 "! pidof rouster-bgpd"

echo "==> final state"
docker exec "$R1" sh -c "vtysh -c 'show bgp ipv4 unicast'" | tail -6
docker exec "$R2" sh -c "ip route show proto bgp; echo '(after teardown)'"

echo "bgp-policy interop: PASS"

# The RS leg (N5 M4): M2's own interop script — our bgpd as the route
# server against two FRR route-server-clients.
echo "==> RS leg: scripts/test-bgp-rs-interop.sh"
bash "$(dirname "$0")/test-bgp-rs-interop.sh"

echo "bgp-policy interop (with RFC 7606 + RS legs): PASS"
