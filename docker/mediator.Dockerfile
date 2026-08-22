# syntax=docker/dockerfile:1
#
# Production mediator image. Build context is the repository ROOT:
#   docker build -f docker/mediator.Dockerfile -t messaging-mediator .
#
# Feature set (must match the deployment contract): the runtime is compiled
# with `secrets-aws`, so the binary can open aws_secrets:// / aws_parameter_store://
# backends. Building without it makes the mediator hard-fail at startup when the
# deployment points MEDIATOR_SECRETS_BACKEND / MEDIATOR_DID at an AWS scheme.
#
# The image ships docker/conf/mediator.toml (the container profile), NOT the
# annotated template — the template names `keyring://`, which is not compiled in
# here and has no OS secret service in a container, and it carries a sample DID
# that must never be baked into a published image. See that file's header for
# the run-time contract; docker/ci/boot-probe.sh asserts both boot paths.
#
# Build caching: cargo-chef caches the dependency graph as a layer keyed on the
# manifests/lockfile, and BuildKit cache mounts keep the cargo registry + target
# dir warm across builds. A source-only change then recompiles just the
# workspace crates instead of the whole graph. Binaries are copied out of the
# (unmounted) target cache inside the build step so they survive into runtime.

ARG RUST_VERSION=1.95.0
ARG PORT=7037
ARG CARGO_CHEF_VERSION=0.1.77

FROM rust:${RUST_VERSION}-slim-bookworm AS chef
WORKDIR /app
# build-essential: cc, needed by jemalloc (a default feature) and openssl-sys.
# pkg-config + libdbus: the cross-platform keyring secret store (pulled by the
# TDK layer) links dbus on Linux. libssl: openssl-sys in the dependency graph.
RUN apt-get update \
    && apt-get install --assume-yes --no-install-recommends \
        build-essential pkg-config libdbus-1-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
ARG CARGO_CHEF_VERSION
RUN cargo install cargo-chef --locked --version ${CARGO_CHEF_VERSION}

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG TARGETARCH
COPY --from=planner /app/recipe.json recipe.json
# Cook dependencies for the exact feature sets used below. The registry/git
# caches are arch-independent; the target cache is scoped per arch.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json -p affinidi-messaging-mediator --features tsp,secrets-aws \
    && cargo chef cook --release --recipe-path recipe.json -p affinidi-messaging-mediator-setup --no-default-features --features secrets-aws,publish-aws
COPY . .
# didcomm + redis-backend + jemalloc come from defaults; add tsp + secrets-aws
# (secrets-aws pulls in the `aws` feature required by aws_secrets:// /
# aws_parameter_store://). mediator-setup carries only the AWS backends used.
RUN --mount=type=cache,id=cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=cargo-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo build --release -p affinidi-messaging-mediator --features tsp,secrets-aws \
    && cargo build --release -p affinidi-messaging-mediator-setup --no-default-features --features secrets-aws,publish-aws \
    && mkdir -p /out \
    && cp target/release/mediator target/release/mediator-setup /out/

# Runtime base pinned by digest: nothing here is rebuilt from source, so the
# digest is the only thing fixing what ships. Bump it to pick up CVE fixes.
FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime
ARG PORT
LABEL org.opencontainers.image.source="https://github.com/affinidi/affinidi-tdk-rs" \
      org.opencontainers.image.title="messaging-mediator" \
      org.opencontainers.image.description="Affinidi Secure Messaging Mediator (DIDComm v2 + TSP)" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update && apt-get install --assume-yes --no-install-recommends ca-certificates && apt-get -y upgrade && apt-get -y autoclean && apt-get -y clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Template assets (atm-functions.lua and friends), then the container config
# overwrites the template's mediator.toml — the mediator defaults to
# `-c conf/mediator.toml` relative to WORKDIR, so this is the file it reads.
COPY crates/messaging/affinidi-messaging-mediator/conf conf
COPY docker/conf/mediator.toml conf/mediator.toml
COPY --from=builder /out/mediator /usr/local/bin
COPY --from=builder /out/mediator-setup /usr/local/bin
RUN groupadd -r lowPrivGroup && useradd -r -g lowPrivGroup lowPrivUser
USER lowPrivUser
EXPOSE $PORT
ENTRYPOINT ["/usr/local/bin/mediator"]
