# affinidi-did-resolver-cache-sdk

[![Crates.io](https://img.shields.io/crates/v/affinidi-did-resolver-cache-sdk.svg)](https://crates.io/crates/affinidi-did-resolver-cache-sdk)
[![Documentation](https://docs.rs/affinidi-did-resolver-cache-sdk/badge.svg)](https://docs.rs/affinidi-did-resolver-cache-sdk)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-cache-sdk)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

SDK for resolving [Decentralised Identifiers (DIDs)](https://www.w3.org/TR/did-1.0/)
with built-in local caching. Operates in **local mode** (resolving happens in
your process) or **network mode** (requests are forwarded to a remote
[cache server](../affinidi-did-resolver-cache-server/)).

## Installation

```toml
[dependencies]
affinidi-did-resolver-cache-sdk = "0.8"
```

## Supported DID Methods

| Method | Default | Feature Flag |
|---|---|---|
| `did:key` | Yes | — |
| `did:peer` | Yes | — |
| `did:web` | Yes | — |
| `did:ethr` | Yes | — |
| `did:pkh` | Yes | — |
| `did:webvh` | Yes | `did-methods` |
| `did:cheqd` | Yes | `did-methods` |
| `did:scid` | Yes | `did-methods` |
| `did:ebsi` | No | `did-ebsi` (EBSI DID Registry API) |
| `did:example` | No | `did_example` (must be manually loaded) |

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `local` | Yes | Reserved for future local-only features |
| `did-methods` | Yes | Includes `did-webvh`, `did-cheqd`, `did-scid` |
| `did-ebsi` | No | EBSI DID method (requires network access to EU API) |
| `network` | No | Enable network mode for remote cache server |
| `did-webvh` | — | WebVH DID method support |
| `did-cheqd` | — | Cheqd blockchain DID method support |
| `did-scid` | — | Self-Certifying Identifier DID method |
| `did_example` | — | Example DID method for testing |

## Usage

### Local Mode (default)

```rust
use affinidi_did_resolver_cache_sdk::{config::ClientConfigBuilder, DIDCacheClient};

let config = ClientConfigBuilder::default().build();
let resolver = DIDCacheClient::new(config).await?;

match resolver.resolve("did:key:z6Mkr...").await {
    Ok(result) => println!("Document: {:#?}", result.doc),
    Err(e) => println!("Error: {:?}", e),
}
```

### Network Mode

Enable the `network` feature, then point to a running cache server:

```rust
let config = ClientConfigBuilder::default()
    .with_network_mode("ws://127.0.0.1:8080/did/v1/ws")
    .with_cache_ttl(60)            // Cache TTL in seconds
    .with_network_timeout(20_000)  // Timeout in milliseconds
    .build();
let resolver = DIDCacheClient::new(config).await?;
```

Network mode still caches locally to reduce remote calls.

## Caching Strategy

The cache uses **per-method TTL** to avoid unnecessary re-resolution:

| Category | Methods | TTL | Rationale |
|---|---|---|---|
| **Immutable** | `did:key`, `did:peer`, `did:jwk`, `did:ethr`, `did:pkh` | None (capacity-evicted only) | Document is derived deterministically from the DID string |
| **Mutable** | `did:web`, `did:webvh`, `did:cheqd`, `did:scid` | Configurable (`cache_ttl`, default 300s) | Document is fetched from external infrastructure and can change |

The `cache_ttl` configuration option only applies to mutable DID methods.
Immutable DIDs stay cached until evicted by capacity pressure, since their
documents can never change.

## Benchmarks

```bash
cargo run --features network --example benchmark -- \
  -g 1000 -r 10000 -n ws://127.0.0.1:8080/did/v1/ws
```

## Running Tests

Integration tests require the `network` feature:

```bash
cargo test --features network
```

## Related Crates

- [`affinidi-did-resolver-cache-server`](../affinidi-did-resolver-cache-server/) — Remote cache server
- [`affinidi-did-common`](../affinidi-did-common/) — DID Document types (dependency)
- [`affinidi-did-resolver-traits`](../affinidi-did-resolver-traits/) — Pluggable resolver traits (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
