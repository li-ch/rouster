# frr-testbed — the FRR side of the smoke suite.
#
# Reversed 2026-10-14 from the locally built frr-testbed:10.2.2 image
# (docker history / /etc/apk/world inspection — see docker/README.md):
# Alpine 3.22 base + the v3.22 community binary package frr=10.2.2-r0.
# NOT a source build, NOT an frrouting/* image pull.
#
# Upstream source anchor (what Alpine packaged; we do not build it):
#   https://codeload.github.com/FRRouting/frr/tar.gz/refs/tags/frr-10.2.2
#   sha256 bbd7a6eccfc0baf1a3bc32481d16438d3e4921493e2aed046acbe111ad36ce83
#
# The exact frr pin is deliberate: a future -rN revision must fail the
# build loudly rather than silently change the daemon under test.
# Equivalence bar: scripts/run-smokes.sh 34/34 green against this
# image run under the frr-testbed:10.2.2 tag.

FROM alpine:3.22

RUN apk add --no-cache \
        frr=10.2.2-r0 \
        iproute2 \
        iputils \
        traceroute \
 && mkdir -p /run/frr /var/log/frr \
 && chown frr:frr /run/frr /var/log/frr

# The original image's entrypoint was a containerlab premise-case
# supervisor; no smoke script uses it (every scripts/ docker run
# overrides the entrypoint), and the lab harness is not part of this
# public repo — so this is the minimal stub.
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
