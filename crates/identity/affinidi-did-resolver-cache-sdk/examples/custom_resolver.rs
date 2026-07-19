//! Register a **custom DID resolver** with the cache client.
//!
//! `DIDCacheClient` resolves each DID method through a chain of pluggable
//! resolvers. This example plugs in a brand-new method, `did:example`, by
//! implementing the sync [`Resolver`] trait — resolution here is pure
//! computation, so the blanket impl turns it into an
//! [`AsyncResolver`](affinidi_did_resolver_cache_sdk::AsyncResolver)
//! automatically. (For a method that needs network or database IO, implement
//! `AsyncResolver` directly instead.)
//!
//! The same pattern also *overrides* a built-in method — register a resolver for
//! `MethodName::Key` and it replaces the built-in `did:key` resolver.
//!
//! Run with:
//! ```sh
//! cargo run --example custom_resolver
//! ```

use affinidi_did_common::{DID, Document};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, MethodName, Resolution, Resolver, ResolverError, config::DIDCacheConfigBuilder,
    errors::DIDCacheError,
};

/// A toy resolver for `did:example:*` that synthesises a minimal DID Document.
///
/// Implementing the **sync** [`Resolver`] trait is the simplest path for a
/// method whose resolution is pure computation; the SDK's blanket impl makes it
/// usable anywhere a `Box<dyn AsyncResolver>` is expected.
struct ExampleResolver;

impl Resolver for ExampleResolver {
    fn name(&self) -> &str {
        "ExampleResolver"
    }

    fn resolve(&self, did: &DID) -> Resolution {
        // Return `None` for anything that isn't ours so the next resolver in the
        // chain gets a turn — this is how composition works.
        if did.method().name() != "example" {
            return None;
        }
        let did_str = did.to_string();
        let doc_json = format!(
            r#"{{"id":"{did_str}","verificationMethod":[],"authentication":[],"assertionMethod":[],"keyAgreement":[],"capabilityInvocation":[],"capabilityDelegation":[],"service":[]}}"#
        );
        Some(
            serde_json::from_str::<Document>(&doc_json)
                .map_err(|e| ResolverError::InvalidDocument(e.to_string())),
        )
    }
}

#[tokio::main]
async fn main() -> Result<(), DIDCacheError> {
    // Local mode — no network calls, resolution runs entirely in-process.
    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await?;

    // Register the custom resolver for the `example` method. Do this during
    // setup, *before* the client is cloned or shared — registration borrows the
    // client mutably and panics if it has already been cloned.
    client.set_resolver(
        MethodName::Other("example".to_string()),
        Box::new(ExampleResolver),
    );

    // Resolve a DID of the brand-new method through the public `resolve()` API —
    // the cache client dispatches to our resolver.
    let response = client.resolve("did:example:alice").await?;
    println!(
        "resolved did:example:alice via a custom resolver -> document id {}",
        response.doc.id
    );

    // Custom resolvers can also override a built-in method: registering for
    // `MethodName::Key` replaces the built-in `did:key` resolver. Use
    // `prepend_resolver`/`append_resolver` to add priority/fallback layers
    // instead of replacing. (Note: `resolve()` caches per-DID, and immutable
    // methods like `did:key` are cached until eviction — register resolvers
    // before resolving, or the cached document is returned.)
    println!("tip: set_resolver(MethodName::Key, ...) overrides the built-in did:key resolver.");

    Ok(())
}
