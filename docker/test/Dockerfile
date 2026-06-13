# syntax=docker/dockerfile:1
#
# TEST-ONLY mediator image for docker-compose.test.yml (TI3).
#
# Build context is the repository ROOT (the build needs the whole workspace):
#   docker build -f docker/test/Dockerfile -t affinidi-mediator-test .
# or via `docker compose -f docker-compose.test.yml build`.
#
# Ships the fixed TEST-ONLY identity from docker/test/conf (file:// secrets
# backend). Never use these keys for anything real.

# Pinned to the workspace toolchain (rust-toolchain.toml). Keep in sync.
FROM rust:1.95-bookworm AS builder
# Native build deps: libdbus-1-dev (keyring backend, compiled in even though the
# test stack uses the file:// backend) + libssl-dev + pkg-config. Mirrors the
# workspace CI's ubuntu-rust-deps.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libdbus-1-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release -p affinidi-messaging-mediator

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/mediator /usr/local/bin/mediator
# Fixed TEST-ONLY config + secrets (committed; file:// backend points at
# /etc/mediator/conf/secrets.json).
COPY docker/test/conf /etc/mediator/conf

WORKDIR /etc/mediator
EXPOSE 7037
CMD ["mediator", "-c", "conf/mediator.toml"]
