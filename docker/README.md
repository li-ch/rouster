# docker/ — the smoke-suite container images

The smoke suite (`scripts/run-smokes.sh`, 34 scripts) runs its evidence
against real daemons in throwaway containers. This directory holds the
in-repo recipes for those images so a clean checkout (and CI) can
reproduce them.

| recipe | image | used by |
|---|---|---|
| `frr-testbed.Dockerfile` | `frr-testbed:10.2.2` / `frr-testbed:ci` | every `test-*interop*`, `test-z5*`, `test-bfd-frr*`, `test-ospf*`, `test-bgp-*`, plus the full-iproute2 scratch bases of `test-vty-smoke`/`test-configd-smoke`/`test-w4*`/`test-w7`/`test-w8` and the `ip` donors of the SAV smokes |
| `nft-base.Dockerfile` | `rouster-nft:local` | `test-sav-nft.sh`, `test-savd-nft.sh` (via `ROUSTER_NFT_BASE_IMAGE`) |

(`docker/Dockerfile` — the Phase-0 rousterd-on-Debian image — is the
legacy pre-suite artifact, kept for history; nothing in `scripts/`
builds or runs it.)

## frr-testbed provenance — recipe reversed from the live image

The suite was developed against a locally built `frr-testbed:10.2.2`.
Its exact recipe was recovered by inspecting the image itself
(`docker history`, `docker inspect`, `/etc/apk/world`,
`/lib/apk/db/installed`; 2026-10-14), not from any build record:

```
FROM alpine:3.22                                  # minirootfs 3.22.5, aarch64
RUN apk add --no-cache frr=10.2.2-r0 iproute2 iputils traceroute \
 && mkdir -p /run/frr /var/log/frr \
 && chown frr:frr /run/frr /var/log/frr
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```

Key facts from that inspection:

- **FRR comes from the Alpine v3.22 community binary package**
  (`frr-10.2.2-r0`, 5.7 MB apk / 24.5 MB installed), *not* from a
  source build and *not* from any `frrouting/frr` docker image.
  `bash` is present only because the apk `frr` package depends on it;
  the other 40-odd packages are base-alpine plus `iproute2`,
  `iputils`, `traceroute` and frr's shared-library closure
  (libyang 2.1.148, json-c 0.18, protobuf-c 1.5.2, c-ares 1.34.8,
  pcre2, readline, ncurses, libcap, openssl).
- **Daemons live in `/usr/lib/frr/`** (zebra, bgpd, ospfd, ospf6d,
  staticd, mgmtd, bfdd, isisd, …) and `vtysh` in `/usr/bin/vtysh` —
  the paths the smoke scripts exec and docker-cp against.
- The original `entrypoint.sh` was a containerlab premise-case
  supervisor (waits for lab links, starts zebra+bgpd in the
  foreground). **No smoke script uses it** — every `docker run` in
  `scripts/` overrides the entrypoint (`--entrypoint sleep …
  infinity` or `--entrypoint sh`). The in-repo `entrypoint.sh` is
  therefore a minimal `exec "$@"` stub, and that difference is
  intentional (the premise-case lab harness is not part of this
  public repo).
- `docker inspect` config: no env beyond the default `PATH`, user
  root, no volumes, `CMD` unset.

What the smokes actually *require* of the image: the frr 10.2.2
daemon set under `/usr/lib/frr` (staticd, mgmtd, zebra-shaped daemons
per script), `vtysh`, full `iproute2` (`ip` with netns/vrf support),
busybox coreutils, `ping`, and musl libc for the docker-cp'd Rouster
binaries. `traceroute` is along for interactive debugging parity.

### Pins

- `frr=10.2.2-r0` is pinned exactly in the Dockerfile, matching the
  reversed recipe. Alpine stable branches do not bump package
  versions; if a security revision (`-r1`) ever lands, the pin fails
  loudly (apk resolution error) instead of silently changing the FRR
  under test — bump the pin deliberately, with the interop notes in
  `docs/interop/frr-10.2-interop.md` in hand.
- Upstream source anchor (what Alpine built the package from; the
  repo deliberately does not build FRR from source):
  `https://codeload.github.com/FRRouting/frr/tar.gz/refs/tags/frr-10.2.2`
  `sha256 bbd7a6eccfc0baf1a3bc32481d16438d3e4921493e2aed046acbe111ad36ce83`
  (computed from the tag archive 2026-10-14; GitHub tag archives are
  not contractually byte-stable — treat as best-effort provenance).
- The base floats within `alpine:3.22.x` (the v3.22 apk repository —
  and therefore the frr package — is identical across those micro
  releases).

### Equivalence

Equivalence of the rebuilt image is defined functionally: the full
suite (34/34) green against it. First proof, 2026-10-14: built as
`frr-testbed:ci` (parity spot-checks: identical `/etc/apk/world`, 41
installed packages, byte-identical vtysh size, `staticd --version`
10.2.2, frr-owned `/run/frr` + `/var/log/frr`) and run via the
`frr-testbed:10.2.2` tag alias — `docker tag frr-testbed:ci
frr-testbed:10.2.2` swaps the suite onto the rebuilt image without
touching a single script. Result: 34/34 green (30 in the sequential
run; the four BFD smokes re-run individually after their quarantine
`cd` into `<repo>/away` failed in the isolated clean-checkout used
for the proof — a worktree environment artifact, not an image
difference; all four green on re-run against the same tags).
The nightly workflow (`.github/workflows/smokes.yml`) builds this
Dockerfile on every run, so the suite is permanently pinned to the
in-repo recipe.

## Building locally

```sh
docker build -t frr-testbed:ci -f docker/frr-testbed.Dockerfile docker/
docker build -t rouster-nft:local -f docker/nft-base.Dockerfile docker/
# put the rebuilt testbed under the tag the scripts pin:
docker tag frr-testbed:ci frr-testbed:10.2.2
```

The `apk add` fetches from `dl-cdn.alpinelinux.org`; everything else
is cached base layers. `scripts/run-smokes.sh` never pulls images —
it and the scripts assume the tags above (plus `gortr:local`, a
retagged `cloudflare/gortr` for `test-rpki-gortr.sh`) already exist.
