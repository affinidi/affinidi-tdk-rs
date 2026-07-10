# syntax=docker/dockerfile:1
#
# Production mediator image. Build context is the repository ROOT:
#   docker build -f docker/mediator.Dockerfile -t messaging-mediator .
#
# Feature set (must match the deployment contract): the runtime is compiled
# with `secrets-aws`, so the binary can open aws_secrets:// / aws_parameter_store://
# backends. Building without it makes the mediator hard-fail at startup when the
# deployment points MEDIATOR_SECRETS_BACKEND / MEDIATOR_DID at an AWS scheme.

ARG RUST_VERSION=1.95.0
ARG PORT=7037

# Base images pinned by digest for reproducible, provenance-friendly builds.
FROM rust:${RUST_VERSION}-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS rust

RUN apt-get update && apt-get install --assume-yes --no-install-recommends build-essential
# pkg-config + libdbus: the cross-platform keyring secret store (pulled by the
# TDK layer) links dbus on Linux. libssl: openssl-sys in the dependency graph.
RUN apt-get install --assume-yes --no-install-recommends pkg-config libdbus-1-dev libssl-dev

FROM rust AS builder
WORKDIR /app
COPY . .
# didcomm + redis-backend come from defaults; add tsp + secrets-aws (secrets-aws
# pulls in the `aws` feature required by aws_secrets:// / aws_parameter_store://).
RUN cargo build --release -p affinidi-messaging-mediator --features tsp,secrets-aws
# mediator-setup: only the AWS backends the cloud deployment uses.
RUN cargo build --release -p affinidi-messaging-mediator-setup \
    --no-default-features --features secrets-aws,publish-aws

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
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
