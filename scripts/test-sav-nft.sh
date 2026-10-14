#!/usr/bin/env bash
# N6 smoke test: the nftables SAV backend (W7B) with a spoof
# differential against the rp_filter baseline.
#
# Same topology and readout discipline as test-w7-sav.sh, but the
# enforcement surface is the nft backend (table inet rouster_sav,
# `w7-sav-smoke --backend nft`), driven through the same Dataplane
# trait ops. The precision this proves over the sysctl baseline:
# the compiled allowlist CONTENT is enforced (a /26 operator list
# blocks a FIB-legit /24 source the rp_filter=1 baseline passes),
# monitor mode counts in kernel counters without dropping anything
# (rp_filter cannot count at all), and the sysctl surface stays
# untouched (rp_filter remains 0 in every leg).
#
# Topology (identical to W7, one container + netns ns1):
#   parent ns: vethlegit 198.51.100.1/24   (egress of the source prefix)
#              vethspoof 192.0.2.1/24      (wrong arrival interface)
#   ns1:       vethlegitp 198.51.100.9/24 (+198.51.100.200/24 for the
#              differential leg)           vethspoofp 192.0.2.9/24
#
# Base image: rouster-nft:local (busybox + nftables v1.0.9 — the
# cached image the W7B ladder was blocked on). busybox `ip` creates
# veths but has no `netns` subcommand, so full iproute2 `ip` (from the
# cached frr-testbed:10.2.2, plus its four missing shared libs) is
# docker-cp'd in — the same binary-delivery class as the smoke binary
# itself; no docker pulls happen.
#
# Legs: ENFORCE+MONITOR (counters rise, nothing drops, sysctl stays 0)
# → PER-OP (N6B: one process installs, drives traffic, reads the
# kernel counters back per op — the deny-all op owns the invalid
# packets, the allowlist op the valid ones)
# → ENFORCE+DROP (spoof 100% loss, legit 0% loss, sysctl still 0)
# → DIFFERENTIAL (/26 allowlist: FIB-legit .200 blocked 100%, .9
# passes 0% — against the rp_filter baseline's 0% for both)
# → CLEAR (table gone, spoof passes again, counts answer zeros)
# → BASELINE (scripts/test-w7-sav.sh re-run into n6/w7-baseline for
# the side-by-side record).
#
#   scripts/test-sav-nft.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

IMAGE=rouster:sav-nft
NAME=rouster-sav-nft
BASE_IMAGE="${ROUSTER_NFT_BASE_IMAGE:-rouster-nft:local}"
IP_DONOR="${ROUSTER_NFT_IP_DONOR:-frr-testbed:10.2.2}"
# away/<program>/quarantine sits next to the rouster repo's parent.
QUARANTINE="${ROUSTER_NFT_QUARANTINE:-$(cd "$(dirname "$0")/../.." && pwd)/away/2026-10-11/night/quarantine/n6}"

case "$(uname -m)" in
    arm64|aarch64) MUSL_TARGET=aarch64-unknown-linux-musl ;;
    x86_64)        MUSL_TARGET=x86_64-unknown-linux-musl ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 1 ;;
esac

capture() {
    mkdir -p "$QUARANTINE"
    docker exec "$NAME" sh -c \
        "nft list ruleset; echo ---; ip -br addr show; ip route show; \
         ip netns exec ns1 ip route show; echo ---; \
         cat /run/rouster/sav-nft.ruleset 2>/dev/null; echo ---; \
         cat /run/rouster/sav-nft-applied 2>/dev/null; echo ---; \
         sysctl net.ipv4.conf.vethlegit.rp_filter net.ipv4.conf.vethspoof.rp_filter" \
        > "$QUARANTINE/state.txt" 2>&1 || true
}

# Loss percentage of one ping run ("x% packet loss"). busybox ping
# exits nonzero on 100% loss -- that is the answer, not an error.
ping_loss() {
    docker exec "$NAME" sh -c "$1; true" 2>/dev/null \
        | grep -o '[0-9]*% packet loss' | head -1 | cut -d% -f1
}

expect_loss() { # <label> <command> <expected %>
    local got
    got="$(ping_loss "$2")"
    echo "    $1: loss=${got:-NO-ANSWER}% (want $3%)"
    [ "${got:-100}" = "$3" ]
}

counts_invalid() {
    docker exec "$NAME" w7-sav-smoke counts --backend nft 2>/dev/null \
        | grep -o 'invalid=[0-9]*' | head -1 | cut -d= -f2
}

echo "==> building w7-sav-smoke ($MUSL_TARGET, release, sav example)"
mkdir -p "$QUARANTINE"
if ! rustup target list --installed | grep -q "$MUSL_TARGET"; then
    rustup target add "$MUSL_TARGET"
fi
cargo build --release --target "$MUSL_TARGET" -p sav --example w7-sav-smoke

echo "==> assembling test image from $BASE_IMAGE"
BUILD_DIR="$(mktemp -d)"
trap 'capture; rm -rf "$BUILD_DIR"; docker rm -f "$NAME" >/dev/null 2>&1 || true' EXIT
cp "target/$MUSL_TARGET/release/examples/w7-sav-smoke" "$BUILD_DIR/w7-sav-smoke"
cat > "$BUILD_DIR/Dockerfile" <<EOF
FROM $BASE_IMAGE
COPY w7-sav-smoke /usr/local/bin/w7-sav-smoke
EOF
docker build -q -t "$IMAGE" "$BUILD_DIR" >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "==> starting container $NAME (cap pattern of test-z5b)"
# apparmor=unconfined: docker's default AppArmor profile carries an
# unconditional `deny mount` (moby profiles/apparmor/template.go) that
# overrides CAP_SYS_ADMIN wherever the LSM is active — Ubuntu runners
# answer the /proc overmount and the `ip netns add` bind-mount with
# "Permission denied" (CI run 38647649951). Locally (no AppArmor on
# the docker VM) this changes nothing; seccomp already permits mount
# for SYS_ADMIN-bounded containers.
docker run -d --name "$NAME" \
    --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN \
    --security-opt apparmor=unconfined \
    --entrypoint sh "$IMAGE" -c 'while true; do sleep 3600; done' >/dev/null

# Environment parity, not a test leg (the w7 note): hosts that bring
# container netns up with nonzero rp_filter defaults would fail the
# baseline below and shadow the differential. The overmount is the w8
# pattern (the nft backend itself never writes sysctls; the baseline
# asserts they are untouched — zero them BEFORE asserting).
docker exec "$NAME" mount -t proc none /proc
docker exec "$NAME" sysctl -q -w \
    net.ipv4.conf.all.rp_filter=0 \
    net.ipv4.conf.default.rp_filter=0 \
    net.ipv4.conf.lo.rp_filter=0

echo "==> delivering full iproute2 ip (busybox has no netns subcommand)"
docker rm -f nft-ip-donor >/dev/null 2>&1 || true
docker create --name nft-ip-donor "$IP_DONOR" >/dev/null
docker cp nft-ip-donor:/sbin/ip "$BUILD_DIR/ip"
# The shared libs are symlinks in the donor (docker cp would preserve
# them as dangling links), so copy each REAL file and re-point the
# soname link inside the container.
for lib in libelf.so.1 libcap.so.2 libz.so.1 libzstd.so.1; do
    real="$(docker run --rm --entrypoint sh "$IP_DONOR" -c "readlink -f /usr/lib/$lib")"
    docker cp "nft-ip-donor:$real" "$BUILD_DIR/$(basename "$real")"
done
docker rm -f nft-ip-donor >/dev/null
docker cp "$BUILD_DIR/ip" "$NAME:/usr/local/bin/ip"
for lib in libelf.so.1 libcap.so.2 libz.so.1 libzstd.so.1; do
    real="$(docker run --rm --entrypoint sh "$IP_DONOR" -c "readlink -f /usr/lib/$lib")"
    docker cp "$BUILD_DIR/$(basename "$real")" "$NAME:$real"
    docker exec "$NAME" ln -sf "$(basename "$real")" "/usr/lib/$lib"
done
docker exec "$NAME" ip -V

echo "==> baseline: no rouster table, no sysctl touches"
[ -z "$(docker exec "$NAME" nft list ruleset)" ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/lo/rp_filter)" = 0 ]

echo "==> topology: two veth pairs, peer ends in netns ns1 (W7 shape)"
docker exec "$NAME" ip link add vethlegit type veth peer name vethlegitp
docker exec "$NAME" ip link add vethspoof type veth peer name vethspoofp
docker exec "$NAME" ip netns add ns1
docker exec "$NAME" ip link set vethlegitp netns ns1
docker exec "$NAME" ip link set vethspoofp netns ns1
docker exec "$NAME" ip addr add 198.51.100.1/24 dev vethlegit
docker exec "$NAME" ip addr add 192.0.2.1/24 dev vethspoof
docker exec "$NAME" ip link set vethlegit up
docker exec "$NAME" ip link set vethspoof up
docker exec "$NAME" ip netns exec ns1 ip addr add 198.51.100.9/24 dev vethlegitp
docker exec "$NAME" ip netns exec ns1 ip addr add 198.51.100.200/24 dev vethlegitp
docker exec "$NAME" ip netns exec ns1 ip addr add 192.0.2.9/24 dev vethspoofp
docker exec "$NAME" ip netns exec ns1 ip link set vethlegitp up
docker exec "$NAME" ip netns exec ns1 ip link set vethspoofp up
docker exec "$NAME" ip netns exec ns1 ip link set lo up

LEGIT_IF="$(docker exec "$NAME" cat /sys/class/net/vethlegit/ifindex)"
SPOOF_IF="$(docker exec "$NAME" cat /sys/class/net/vethspoof/ifindex)"
echo "    vethlegit ifindex=$LEGIT_IF  vethspoof ifindex=$SPOOF_IF"

SPOOF_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 192.0.2.1'
LEGIT_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.9 198.51.100.1'
SPARSE_CMD='ip netns exec ns1 ping -c3 -W1 -I 198.51.100.200 198.51.100.1'

echo "==> [monitor leg] strict IBA, default Monitor action, nft backend"
docker exec "$NAME" w7-sav-smoke install --mode strict --action monitor \
    --backend nft \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    >"$QUARANTINE/monitor-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/monitor-install.log"
# ENFORCE(monitor): the kernel holds the counter-bearing table, no
# drop verdict anywhere, and the sysctl surface is untouched.
docker exec "$NAME" nft list table inet rouster_sav >"$QUARANTINE/monitor-ruleset.txt"
grep -q 'hook prerouting priority raw' "$QUARANTINE/monitor-ruleset.txt"
grep -q 'counter name "i_vethspoof' "$QUARANTINE/monitor-ruleset.txt"
! grep -qw drop "$QUARANTINE/monitor-ruleset.txt"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethlegit/rp_filter)" = 0 ]
echo "    ENFORCE(monitor): table installed, counters present, no drop, rp_filter still 0/0"

# MONITOR-DEFAULT: nothing drops (spoof and legit both pass)...
expect_loss "MONITOR-DEFAULT spoof passes" "$SPOOF_CMD" 0
expect_loss "LEGIT-PASS (monitor)" "$LEGIT_CMD" 0
# ...and the KERNEL counters rise (the dataplane-first path the
# rp_filter backend cannot answer): spoofed requests land in the
# invalid bucket, legit ones in the valid bucket.
INV0="$(counts_invalid)"
VAL0="$(docker exec "$NAME" w7-sav-smoke counts --backend nft 2>/dev/null | grep -o ' valid=[0-9]*' | head -1 | cut -d= -f2)"
docker exec "$NAME" sh -c "$SPOOF_CMD" >/dev/null 2>&1 || true
docker exec "$NAME" sh -c "$LEGIT_CMD" >/dev/null 2>&1 || true
docker exec "$NAME" w7-sav-smoke counts --backend nft >"$QUARANTINE/monitor-counts.log" 2>&1
INV1="$(grep -o 'invalid=[0-9]*' "$QUARANTINE/monitor-counts.log" | head -1 | cut -d= -f2)"
VAL1="$(grep -o ' valid=[0-9]*' "$QUARANTINE/monitor-counts.log" | head -1 | cut -d= -f2)"
[ "$INV1" -ge $(( ${INV0:-0} + 3 )) ]
[ "$VAL1" -ge $(( ${VAL0:-0} + 3 )) ]
echo "    MONITOR-DEFAULT: kernel counters rose (invalid ${INV0:-0}->$INV1, valid ${VAL0:-0}->$VAL1)"

echo "==> [per-op leg] N6B: one process — install (churn-guarded), traffic, per-op readback"
# The nft per-op attribution is install-scoped (counter names are
# minted at install time), so the proof runs where the installer and
# the reader are one process: `monitor-round` re-installs the SAME
# program (the churn guard skips the rewrite — the earlier legs'
# counters must carry over), runs both traffic classes, and prints the
# aggregate line plus one row per placed op before and after.
docker exec "$NAME" w7-sav-smoke monitor-round --mode strict --action monitor \
    --backend nft \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    --run "$SPOOF_CMD" --run "$LEGIT_CMD" \
    >"$QUARANTINE/monitor-per-op.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/monitor-per-op.log"
# Churn guard held: the round's BEFORE aggregate is at least what the
# previous legs accumulated (a rewrite would have reset it to ~0).
ROUND_INV_BEFORE="$(grep -o 'sav-round-before: invalid=[0-9]*' "$QUARANTINE/monitor-per-op.log" | cut -d= -f2)"
[ "$ROUND_INV_BEFORE" -ge "$INV1" ]
op_row_invalid() { # <phase> <ifindex>
    grep "sav-round-op-$1: allow if#$2 \[" "$QUARANTINE/monitor-per-op.log" \
        | grep -o 'invalid=[0-9]*' | cut -d= -f2
}
op_row_valid() { # <phase> <ifindex>
    grep "sav-round-op-$1: allow if#$2 \[" "$QUARANTINE/monitor-per-op.log" \
        | grep -o ' valid=[0-9]*' | cut -d= -f2
}
SPOOF_INV_BEFORE="$(op_row_invalid before "$SPOOF_IF")"
SPOOF_INV_AFTER="$(op_row_invalid after "$SPOOF_IF")"
LEGIT_VAL_BEFORE="$(op_row_valid before "$LEGIT_IF")"
LEGIT_VAL_AFTER="$(op_row_valid after "$LEGIT_IF")"
[ -n "$SPOOF_INV_AFTER" ] && [ -n "$LEGIT_VAL_AFTER" ]
[ "$SPOOF_INV_AFTER" -ge $(( ${SPOOF_INV_BEFORE:-0} + 3 )) ]
[ "$LEGIT_VAL_AFTER" -ge $(( ${LEGIT_VAL_BEFORE:-0} + 3 )) ]
echo "    PER-OP: deny-all op invalid ${SPOOF_INV_BEFORE:-?}->$SPOOF_INV_AFTER, allowlist op valid ${LEGIT_VAL_BEFORE:-?}->$LEGIT_VAL_AFTER (counters carried over: before-aggregate $ROUND_INV_BEFORE)"

echo "==> [drop leg] strict IBA, explicit Drop action"
docker exec "$NAME" w7-sav-smoke install --mode strict --action drop \
    --backend nft \
    --iba "$LEGIT_IF:198.51.100.0/24" --iba "$SPOOF_IF" \
    >"$QUARANTINE/drop-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/drop-install.log"
# ENFORCE(drop): the deny is in force in the table, not in sysctls.
docker exec "$NAME" nft list table inet rouster_sav >"$QUARANTINE/drop-ruleset.txt"
grep -qw drop "$QUARANTINE/drop-ruleset.txt"
[ "$(docker exec "$NAME" cat /proc/sys/net/ipv4/conf/vethspoof/rp_filter)" = 0 ]
echo "    ENFORCE(drop): deny verdicts live in the nft table; rp_filter stays 0"

# SPOOF-BLOCK: the spoofed source is 100% blocked; dropped packets
# still count (the counter rides the deny rule).
INV0="$(counts_invalid)"
expect_loss "SPOOF-BLOCK (drop)" "$SPOOF_CMD" 100
expect_loss "LEGIT-PASS (drop)" "$LEGIT_CMD" 0
INV1="$(counts_invalid)"
[ "$INV1" -ge $(( ${INV0:-0} + 3 )) ]
echo "    SPOOF-BLOCK: spoof 100% loss, legit 0% loss, invalid counter ${INV0:-0}->$INV1"

echo "==> [differential leg] /26 operator allowlist: content enforced, not the FIB"
# vethlegit's allowlist narrows to 198.51.100.0/26 (.9 is inside,
# .200 is outside but FIB-legit: same connected /24, same egress
# interface -- rp_filter=1 passes both; the nft backend enforces the
# list content and blocks .200).
docker exec "$NAME" w7-sav-smoke install --mode strict --action drop \
    --backend nft \
    --iba "$LEGIT_IF:198.51.100.0/26" --iba "$SPOOF_IF" \
    >"$QUARANTINE/diff-install.log" 2>&1
grep -q 'sav-install ok' "$QUARANTINE/diff-install.log"
docker exec "$NAME" nft list table inet rouster_sav >"$QUARANTINE/diff-ruleset.txt"
grep -q 'elements = { 198.51.100.0/26 }' "$QUARANTINE/diff-ruleset.txt"
expect_loss "DIFF in-list .9 passes" "$LEGIT_CMD" 0
expect_loss "DIFF FIB-legit .200 blocked (list content)" "$SPARSE_CMD" 100
echo "    DIFFERENTIAL: rp_filter baseline passes .200 (w7: loss 0); nft /26 list blocks it (loss 100)"

echo "==> clear: table destroyed, marker and ruleset file gone"
docker exec "$NAME" w7-sav-smoke clear --backend nft >"$QUARANTINE/clear.log" 2>&1
grep -q 'sav-clear ok' "$QUARANTINE/clear.log"
if docker exec "$NAME" nft list table inet rouster_sav >/dev/null 2>&1; then
    echo "table still present after clear" >&2; exit 1
fi
docker exec "$NAME" sh -c '[ ! -e /run/rouster/sav-nft.ruleset ] && [ ! -e /run/rouster/sav-nft-applied ]'
expect_loss "post-clear spoof passes again" "$SPOOF_CMD" 0
# counts after clear: no table, honest zeros (not an error).
docker exec "$NAME" w7-sav-smoke counts --backend nft >"$QUARANTINE/clear-counts.log" 2>&1
grep -q 'sav-counts: invalid=0 valid=0 unknown=0' "$QUARANTINE/clear-counts.log"
echo "    clear: table/ruleset/marker gone, spoof passes, counts answer zeros"

echo "==> [baseline] rp_filter script re-run for the side-by-side record"
if ! ROUSTER_W7_QUARANTINE="$QUARANTINE/w7-baseline" scripts/test-w7-sav.sh \
        >"$QUARANTINE/w7-baseline-run.log" 2>&1; then
    echo "w7 baseline failed; log preserved at $QUARANTINE/w7-baseline-run.log" >&2
    exit 1
fi
grep -q 'w7 sav spoof test: PASS' "$QUARANTINE/w7-baseline-run.log"
{
    echo "# Spoof differential: nft backend vs rp_filter baseline (same topology)"
    echo
    echo "| traffic | rp_filter=1 (baseline w7) | nft drop (allowlist /24) | nft drop (allowlist /26) |"
    echo "|---|---|---|---|"
    echo "| spoofed 198.51.100.9 \@ vethspoof | 100% loss | 100% loss | 100% loss |"
    echo "| legit .9 \@ vethlegit | 0% loss | 0% loss | 0% loss (in /26) |"
    echo "| FIB-legit .200 \@ vethlegit | 0% loss (not tested; FIB-egress passes strict uRPF) | n/a | 100% loss (outside /26) |"
    echo "| monitor mode | passes, NO kernel counter (simulation only) | passes + kernel counters | n/a |"
    echo "| sysctl rp_filter after install | 1 | 0 (untouched) | 0 (untouched) |"
} > "$QUARANTINE/differential.md"
cat "$QUARANTINE/differential.md"

echo "nft sav spoof test: PASS"
