# affinidi-did-resolver-traits

[![Crates.io](https://img.shields.io/crates/v/affinidi-did-resolver-traits.svg)](https://crates.io/crates/affinidi-did-resolver-traits)
[![Documentation](https://docs.rs/affinidi-did-resolver-traits/badge.svg)](https://docs.rs/affinidi-did-resolver-traits)
[![Rust](https://img.shields.io/badge/rust-1.90.0%2B-blue.svg?maxAge=3600)](https://github.com/affinidi/affinidi-tdk-rs/tree/main/crates/affinidi-did-resolver/affinidi-did-resolver-traits)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)

Pluggable DID resolution traits for the Affinidi TDK. Implement these traits to
add custom DID method support to the resolver.

## Installation

```toml
[dependencies]
affinidi-did-resolver-traits = "0.1"
```

## Traits

- **`Resolver`** (sync) — for methods requiring no IO (e.g., `did:key`, `did:peer`)
- **`AsyncResolver`** (async, dyn-compatible) — for methods requiring network access

Every `Resolver` is automatically an `AsyncResolver` via a blanket impl, so the
SDK composes all resolvers uniformly.

## Return Convention

Resolvers return `Option<Result<Document, ResolverError>>`:

| Return Value | Meaning |
|---|---|
| `None` | Not my DID method — pass to the next resolver |
| `Some(Ok(doc))` | Resolved successfully |
| `Some(Err(e))` | Recognised the DID but resolution failed |

## Built-in Resolvers

- **`KeyResolver`** — resolves `did:key` (Ed25519, P-256, P-384, secp256k1, X25519)
- **`PeerResolver`** — resolves `did:peer` (numalgo 0 and 2)

## Custom Resolver Example

```rust
use affinidi_did_resolver_traits::{AsyncResolver, Resolution};
use affinidi_did_common::DID;
use std::future::Future;
use std::pin::Pin;

struct MyResolver;

impl AsyncResolver for MyResolver {
    fn name(&self) -> &str { "MyResolver" }

    fn resolve<'a>(
        &'a self, did: &'a DID,
    ) -> Pin<Box<dyn Future<Output = Resolution> + Send + 'a>> {
        Box::pin(async move {
            if did.to_string().starts_with("did:mymethod:") {
                // Your resolution logic here
                todo!()
            } else {
                None
            }
        })
    }
}
```

## Related Crates

- [`affinidi-did-common`](../affinidi-did-common/) — DID Document types (dependency)
- [`affinidi-did-resolver-cache-sdk`](../affinidi-did-resolver-cache-sdk/) — SDK that uses these traits

## License

[Apache-2.0](https://github.com/affinidi/affinidi-tdk-rs/blob/main/LICENSE)
