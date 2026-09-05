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
| `did:ethr` | No | `did-ethr` (opt-in — pulls the `ssi-*` stack, see below) |
| `did:pkh` | No | `did-pkh` (opt-in — pulls the `ssi-*` stack, see below) |
| `did:webvh` | Yes | `did-methods` |
| `did:scid` | Yes | `did-methods` |
| `did:cheqd` | **Retired** | parses, but is no longer resolved — see below |
| `did:ebsi` | No | `did-ebsi` (EBSI DID Registry API) |
| `did:webs` | No | `affinidi-did-webs` (KERI-verified key state) |
| `did:example` | No | `did_example` (must be manually loaded) |

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `local` | Yes | Reserved for future local-only features |
| `did-methods` | Yes | Includes `did-webvh`, `did-scid` |
| `did-ethr` | No | `did:ethr` resolution. Pulls the `ssi-*` stack, which pins `p256`/`k256` 0.13 — enabling it puts two generations of the elliptic-curve stack in your graph. |
| `did-pkh` | No | `did:pkh` resolution. Same `ssi-*` cost as `did-ethr`. |
| `did-ebsi` | No | EBSI DID method (requires network access to EU API) |
| `did-webs` | No | did:webs — did:web discovery with a KERI-verified key event log |
| `network` | No | Enable network mode for remote cache server |
| `did-webvh` | — | WebVH DID method support |
| `did-cheqd` | No | Inert since 0.8.36 — retained so enabling it still builds |
| `did-scid` | — | Self-Certifying Identifier DID method |
| `did_example` | — | Example DID method for testing |

### `did:ethr`, `did:pkh` and `did:jwk` are resolved in-tree

These three methods are implemented by `affinidi-did-ethr`, `affinidi-did-pkh`
and `affinidi-did-jwk` in this workspace, not by the spruceid crates of the
same names. Enabling them costs three small dependencies rather than the whole
`ssi-*` stack. See each crate's README for scope and conformance.

### `did:cheqd` resolution was retired in 0.8.36

`did:cheqd` still **parses** — `DIDMethod::Cheqd` is unchanged in
`affinidi-did-common` — but this SDK no longer **resolves** it. `CheqdResolver`
still exists under the `did-cheqd` feature and now declines with an explanatory
`ResolutionFailed`.

The implementation came from `did-resolver-cheqd`: a crate with no published
source repository, a single release from 2025, pinning `ssi-dids-core 0.1`. It
was off by default and enabled by nothing in this workspace, yet its presence as
an optional dependency put eight advisories into `Cargo.lock` — seven
unmaintained crates plus a live `h2` denial-of-service that had to be suppressed
in CI to keep the build green. Removing it cleared all eight and dropped 122
crates from the resolved graph. It also removed the `tonic 0.12` / rustls `ring`
conflict that made this feature awkward to enable in the first place.

Nothing was removed from the public API: the feature, the resolver type and
`ScidMethod::Cheqd` all remain, so code that named them still compiles.

To resolve `did:cheqd`, append your own resolver — the chain is a public
extension point for exactly this:

```rust,ignore
client.append_resolver(MethodName::Cheqd, Box::new(MyCheqdResolver));
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
| **Immutable** | `did:key`, `did:peer`, `did:jwk`, `did:ethr`, `did:pkh` (last three feature-gated) | None (capacity-evicted only) | Document is derived deterministically from the DID string |
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
