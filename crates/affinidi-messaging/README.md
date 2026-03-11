# Affinidi Messaging

[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-messaging)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Secure, private, and trusted messaging built on the
[DIDComm v2](https://identity.foundation/didcomm-messaging/spec/) and
[Trust Spanning Protocol (TSP)](https://trustoverip.github.io/tswg-tsp-specification/)
protocols. Affinidi Messaging leverages
[Decentralised Identifiers (DIDs)](https://www.w3.org/TR/did-1.0/) to provide
end-to-end encrypted, authenticated digital communication.

> **Disclaimer:** This project is provided "as is" without warranties or
> guarantees. Users assume all risks associated with its deployment and use.

## Architecture

```mermaid
graph LR
    A["Alice<br/>(SDK Client)"] -->|DIDComm / TSP| M["Mediator<br/>(Relay Service)"]
    M -->|DIDComm / TSP| B["Bob<br/>(SDK Client)"]
    M ---|Storage| R[(Redis)]
    A -.->|Resolve DIDs| DR["DID Resolver"]
    B -.->|Resolve DIDs| DR
```

Messages are end-to-end encrypted using the recipient's DID public keys. The
mediator routes and stores messages but **cannot** read their content.

## Crates

| Crate | Description |
|---|---|
| [`affinidi-messaging-sdk`](./affinidi-messaging-sdk/) | SDK for integrating messaging into your application |
| [`affinidi-messaging-didcomm`](./affinidi-messaging-didcomm/) | DIDComm v2.1 protocol implementation |
| [`affinidi-messaging-core`](./affinidi-messaging-core/) | Protocol-agnostic messaging traits |
| [`affinidi-messaging-mediator`](./affinidi-messaging-mediator/) | Mediator & relay service (DIDComm and TSP support via feature flags) |
| [`affinidi-messaging-helpers`](./affinidi-messaging-helpers/) | Setup tools, environment config, and example runners |
| [`affinidi-tsp`](./affinidi-tsp/) | Trust Spanning Protocol implementation (HPKE-Auth, CESR) |
| [`affinidi-messaging-text-client`](./affinidi-messaging-text-client/) | Terminal-based DIDComm chat client |

**Dependencies:**
[affinidi-did-resolver](../affinidi-did-resolver/) for DID Document resolution.

## Getting Started

### Prerequisites

- Rust 1.90.0+ (2024 Edition)
- Docker (for Redis)
- Redis 8.0+

### 1. Start Redis

```bash
docker run --name=redis-local --publish=6379:6379 --hostname=redis \
  --restart=on-failure --detach redis:latest
```

### 2. Configure the Mediator

Run from the `affinidi-messaging` directory:

```bash
cargo run --bin setup_environment
```

This generates:
- Mediator DID and secrets
- Administration DID and secrets
- SSL certificates for local development
- Optionally, test user DIDs

### 3. Start the Mediator

```bash
cd affinidi-messaging-mediator
export REDIS_URL=redis://@localhost:6379
cargo run
```

### 4. Run Examples

Go to [affinidi-messaging-helpers](./affinidi-messaging-helpers/) to explore
available examples including trust pings, sending/receiving messages, and message
pickup.

## Related Crates

- [`affinidi-did-resolver`](../affinidi-did-resolver/) — DID resolution and caching
- [`affinidi-tdk`](../affinidi-tdk/) — Unified TDK entry point
- [`affinidi-meeting-place`](../affinidi-meeting-place/) — Secure discovery and connection
- [`affinidi-cesr`](../affinidi-tdk/common/affinidi-cesr/) — CESR codec used by TSP

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
