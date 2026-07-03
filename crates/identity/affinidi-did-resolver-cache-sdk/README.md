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
| `did:scid` | Yes | `did-methods` |
| `did:cheqd` | No | `did-cheqd` (opt-in — pulls a `ring` TLS backend, see below) |
| `did:ebsi` | No | `did-ebsi` (EBSI DID Registry API) |
| `did:example` | No | `did_example` (must be manually loaded) |

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `local` | Yes | Reserved for future local-only features |
| `did-methods` | Yes | Includes `did-webvh`, `did-scid` |
| `did-ebsi` | No | EBSI DID method (requires network access to EU API) |
| `network` | No | Enable network mode for remote cache server |
| `did-webvh` | — | WebVH DID method support |
| `did-cheqd` | No | Cheqd blockchain DID method support (opt-in, see TLS note) |
| `did-scid` | — | Self-Certifying Identifier DID method |
| `did_example` | — | Example DID method for testing |

### `did-cheqd` and the rustls `ring` backend

`did-cheqd` is **not** enabled by default. It pulls `did-resolver-cheqd`, whose
gRPC client (`tonic 0.12`) hardcodes the `ring` backend on
`tokio-rustls`/`rustls 0.23`. This SDK's `network` feature — and most downstream
binaries (via `kube`, `reqwest`, `jsonwebtoken`, …) — select the `aws_lc_rs`
backend instead. When both backends are compiled, `rustls` cannot auto-select
one and panics at the first TLS call with:

```text
no process-level CryptoProvider available
```

If you enable `did-cheqd`, you accept the `ring` backend. Because installing a
process-global `CryptoProvider` is the application's decision, your binary's
`main` must do it before any TLS is used, e.g.:

```rust,ignore
rustls::crypto::aws_lc_rs::default_provider()
    .install_default()
    .expect("install default rustls CryptoProvider");
```

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

### Custom Resolvers

Each DID method is resolved through a chain of pluggable resolvers. You can
replace, extend, or add priority/fallback layers for a method by implementing a
resolver trait and registering it on the client.

Implement the **sync** [`Resolver`] trait when resolution is pure computation
(the SDK's blanket impl makes it an `AsyncResolver` automatically), or implement
[`AsyncResolver`] directly when it needs network/database IO. A resolver returns
`None` for DIDs it doesn't handle, so the next resolver in the chain gets a turn.

```rust
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, MethodName, Resolution, Resolver};
use affinidi_did_common::{DID, Document};

struct StubKeyResolver;
impl Resolver for StubKeyResolver {
    fn name(&self) -> &str { "StubKeyResolver" }
    fn resolve(&self, did: &DID) -> Resolution {
        if did.method().name() != "key" { return None; }
        // ... build and return Some(Ok(document)) ...
    }
}

let mut client = DIDCacheClient::new(config).await?;
client.set_resolver(MethodName::Key, Box::new(StubKeyResolver)); // replaces the built-in
```

Registration API:

- `set_resolver(method, r)` — replace all resolvers for a method with `r`.
- `prepend_resolver(method, r)` — try `r` first, then fall through to existing (e.g. override-with-fallback).
- `append_resolver(method, r)` — try `r` last (fallback).
- `clear_resolvers` / `remove_resolver` / `find_resolver` — manage the chain.

**Register during setup, before the client is cloned/shared** — registration
takes `&mut self` and panics if the client has already been cloned.

**Caching interaction:** `resolve()` checks the cache first, so re-registering a
resolver does not affect DIDs already cached (immutable methods like `did:key`
are cached until capacity-evicted). Register resolvers before resolving, or use a
fresh client.

**Brand-new methods:** registering a resolver for a method with no built-in
support (e.g. `did:example`) works through the public `resolve()` API — an
unrecognised method is tagged `DIDMethod::OTHER` and dispatched to the
registered resolver (the concrete name is preserved in `ResolveResponse::did`).
If no resolver is registered for the method, `resolve()` returns
`UnsupportedMethod`.

Runnable example: [`examples/custom_resolver.rs`](examples/custom_resolver.rs) —
`cargo run --example custom_resolver`.

[`Resolver`]: https://docs.rs/affinidi-did-resolver-traits
[`AsyncResolver`]: https://docs.rs/affinidi-did-resolver-traits

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
