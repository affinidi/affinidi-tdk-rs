# syntax=docker/dockerfile:1
#
# Production mediator image. Build context is the repository ROOT:
#   docker build -f docker/mediator.Dockerfile -t messaging-mediator .

ARG RUST_VERSION=1.95.0
ARG PORT=7037

FROM rust:${RUST_VERSION}-slim-bookworm AS rust

RUN apt-get update && apt-get install --assume-yes --no-install-recommends build-essential
# libdbus: keyring secret backend; libssl; libchafa
RUN apt-get install --assume-yes libdbus-1-dev libssl-dev libchafa-dev

FROM rust AS builder
WORKDIR /app
COPY . .
RUN cargo build --release \
    -p affinidi-messaging-mediator \
    -p affinidi-messaging-mediator-setup

FROM debian:bookworm-slim AS runtime
ARG PORT
RUN apt-get update && apt-get install --assume-yes --no-install-recommends ca-certificates && apt-get -y upgrade && apt-get -y autoclean && apt-get -y clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY crates/messaging/affinidi-messaging-mediator/conf conf
COPY --from=builder /app/target/release/mediator /usr/local/bin
COPY --from=builder /app/target/release/mediator-setup /usr/local/bin
RUN groupadd -r lowPrivGroup && useradd -r -g lowPrivGroup lowPrivUser
USER lowPrivUser
EXPOSE $PORT
ENTRYPOINT ["/usr/local/bin/mediator"]
