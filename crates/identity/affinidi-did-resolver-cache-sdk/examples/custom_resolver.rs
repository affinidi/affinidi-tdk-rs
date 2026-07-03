//! Register a **custom DID resolver** with the cache client.
//!
//! `DIDCacheClient` resolves each DID method through a chain of pluggable
//! resolvers. This example swaps in a custom resolver for a built-in method
//! (`did:key`) by implementing the sync [`Resolver`] trait — resolution here is
//! pure computation, so the blanket impl turns it into an
//! [`AsyncResolver`](affinidi_did_resolver_cache_sdk::AsyncResolver)
//! automatically. (For a method that needs network or database IO, implement
//! `AsyncResolver` directly instead.)
//!
//! This pattern is useful for tests (a deterministic mock resolver), for
//! swapping in an alternate/self-hosted resolution backend, or for adding a
//! caching/transform layer in front of a method.
//!
//! Run with:
//! ```sh
//! cargo run --example custom_resolver
//! ```
//!
//! ## Note on brand-new methods
//!
//! Registering a resolver for a method that is **already built in** (`did:key`,
//! `did:web`, `did:ethr`, …) works through the public [`DIDCacheClient::resolve`]
//! API, as shown here. A resolver for a *genuinely new* method (e.g.
//! `did:example`) is not yet reachable via `resolve()` — the public entry point
//! validates the method against the built-in `DIDMethod` set first. See the
//! crate README ("Custom resolvers") for details.

use affinidi_did_common::{DID, Document};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, MethodName, Resolution, Resolver, ResolverError, config::DIDCacheConfigBuilder,
    errors::DIDCacheError,
};

// Two distinct Ed25519 did:key values. The cache is keyed per-DID, and did:key
// is immutable (cached forever once resolved), so we resolve one with the
// built-in and a *different*, not-yet-cached one with the custom resolver — a
// re-resolve of the same DID would return the cached result and never reach the
// newly-registered resolver.
const DID_KEY_BUILTIN: &str = "did:key:z6MkiToqovww7vYtxm1xNM15u9JzqzUFZ1k7s7MazYJUyAxv";
const DID_KEY_CUSTOM: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/// A custom `did:key` resolver that returns a minimal, deterministic Document
/// instead of deriving one from the key material — the kind of stub a test
/// suite might register to avoid real key expansion.
///
/// Implementing the **sync** [`Resolver`] trait is the simplest path for a
/// resolver whose work is pure computation; the SDK's blanket impl makes it
/// usable anywhere a `Box<dyn AsyncResolver>` is expected.
struct StubKeyResolver;

impl Resolver for StubKeyResolver {
    fn name(&self) -> &str {
        "StubKeyResolver"
    }

    fn resolve(&self, did: &DID) -> Resolution {
        // Return `None` for anything that isn't ours so the next resolver in the
        // chain gets a turn — this is how composition works.
        if did.method().name() != "key" {
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

    // Baseline: the built-in did:key resolver derives verification methods from
    // the key material (Ed25519 yields 2).
    let before = client.resolve(DID_KEY_BUILTIN).await?;
    println!(
        "built-in did:key resolver -> {} verification method(s)",
        before.doc.verification_method.len()
    );

    // Register the custom resolver for the `key` method. `set_resolver` REPLACES
    // the built-in for that method; use `prepend_resolver`/`append_resolver` to
    // add priority/fallback layers instead. Do this during setup, *before* the
    // client is cloned or shared — registration borrows the client mutably and
    // panics if it has already been cloned.
    client.set_resolver(MethodName::Key, Box::new(StubKeyResolver));

    // Resolve a *different* did:key (not yet cached) — the public resolve() call
    // now dispatches to our stub, which returns 0 verification methods.
    let after = client.resolve(DID_KEY_CUSTOM).await?;
    println!(
        "custom  did:key resolver -> {} verification method(s) (document id: {})",
        after.doc.verification_method.len(),
        after.doc.id
    );

    Ok(())
}
