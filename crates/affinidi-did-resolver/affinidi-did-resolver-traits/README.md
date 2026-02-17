# affinidi-did-resolver-traits

Pluggable DID resolution traits for the Affinidi TDK.

## Traits

- **`Resolver`** (sync) — for methods requiring no IO (e.g., `did:key`, `did:peer`)
- **`AsyncResolver`** (async, dyn-compatible) — for methods requiring network access

Every `Resolver` is automatically an `AsyncResolver` via blanket impl, so the SDK can compose all resolvers uniformly as `Vec<Box<dyn AsyncResolver>>`.

## Return Convention

Resolvers return `Option<Result<Document, ResolverError>>`:

- `None` — not my DID, pass to next resolver
- `Some(Ok(doc))` — resolved successfully
- `Some(Err(e))` — recognized the DID but resolution failed

## Built-in Resolvers

- `KeyResolver` — resolves `did:key` (Ed25519, P-256, P-384, secp256k1, X25519)
- `PeerResolver` — resolves `did:peer` (numalgo 0 and 2)

## Custom Resolver Example

```rust
use affinidi_did_resolver_traits::{AsyncResolver, Resolution};
use affinidi_did_common::DID;
use std::future::Future;
use std::pin::Pin;

struct MyResolver;

impl AsyncResolver for MyResolver {
    fn resolve(&self, did: &DID) -> Pin<Box<dyn Future<Output = Resolution> + Send + '_>> {
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

## License

Apache-2.0
