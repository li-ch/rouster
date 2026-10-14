# rouster-nft — full iproute2 + nftables base for the SAV smokes.
#
# Reversed from the locally committed rouster-nft:local image
# (alpine:3.20 + `apk add --no-cache nftables`; 2026-10-14).
# Pinned by test-sav-nft.sh / test-savd-nft.sh via
# ROUSTER_NFT_BASE_IMAGE (default rouster-nft:local).

FROM alpine:3.20

RUN apk add --no-cache nftables
