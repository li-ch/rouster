# Rouster Phase 0 test image: rousterd + iproute2 on Debian.
# FRR daemons join via the frrouting/frr image in Containerlab (Phase 1).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --bin rousterd

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/rousterd /usr/local/bin/rousterd
ENTRYPOINT ["rousterd"]
