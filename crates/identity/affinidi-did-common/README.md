# affinidi-did-common

[![Crates.io](https://img.shields.io/crates/v/affinidi-did-common.svg)](https://crates.io/crates/affinidi-did-common)
[![Documentation](https://docs.rs/affinidi-did-common/badge.svg)](https://docs.rs/affinidi-did-common)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-common)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Common types, builders, and methods for working with
[Decentralised Identifiers (DIDs)](https://www.w3.org/TR/did-1.1/) and DID
Documents. This crate is the foundation for the Affinidi DID Resolver.

## Installation

```toml
[dependencies]
affinidi-did-common = "0.3"
```

## Feature Flags

| Feature | Default | Description |
|---|---|---|
| `ed25519` | Yes | Ed25519 key support |
| `p256` | Yes | P-256 (secp256r1) key support |
| `p384` | Yes | P-384 key support |
| `k256` | Yes | secp256k1 key support |

## Usage

### Building a DID Document

```rust
use affinidi_did_common::{DocumentBuilder, ServiceBuilder, VerificationMethodBuilder};
use serde_json::json;

// Build a verification method
let vm = VerificationMethodBuilder::new("did:example:123#key-1", "Multikey", "did:example:123")
    .unwrap()
    .public_key_multibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
    .build();

// Build a service
let service = ServiceBuilder::new_with_url("LinkedDomains", "https://example.com")
    .unwrap()
    .id("did:example:123#linked-domain")
    .unwrap()
    .build();

// Assemble the document
let doc = DocumentBuilder::new("did:example:123")
    .unwrap()
    .context_did_v1()
    .context_multikey_v1()
    .verification_method(vm)
    .authentication_reference("did:example:123#key-1")
    .unwrap()
    .service(service)
    .build();
```

### Service Endpoint Variants

| Endpoint Form | Constructor |
|---|---|
| Single URL string | `ServiceBuilder::new_with_url("type", "https://...")` |
| Map or ordered set | `ServiceBuilder::new_with_map("type", json!({...}))` |
| Pre-built `Endpoint` | `ServiceBuilder::new("type", endpoint)` |

## Related Crates

- [`affinidi-did-resolver-cache-sdk`](../affinidi-did-resolver-cache-sdk/) — DID resolution SDK (depends on this)
- [`affinidi-did-resolver-traits`](../affinidi-did-resolver-traits/) — Pluggable resolver traits (depends on this)
- [`affinidi-crypto`](../../affinidi-tdk/common/affinidi-crypto/) — Cryptographic primitives (dependency)

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
