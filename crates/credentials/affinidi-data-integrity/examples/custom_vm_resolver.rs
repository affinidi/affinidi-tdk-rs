//! Custom [`VerificationMethodResolver`] skeleton.
//!
//! The library ships [`DidKeyResolver`] for `did:key:` URIs (fully
//! offline, zero I/O). For `did:web`, `did:webvh`, `did:peer`, or
//! any custom DID method, implement the trait once and pass your
//! resolver to `DataIntegrityProof::verify` like any other.
//!
//! This example shows a **stub** resolver that pretends to fetch DID
//! documents from an in-memory map. Replace the `fetch` body with an
//! HTTP call for real did:web, or a delegate to
//! `affinidi-did-resolver-cache-sdk` for cache-backed resolution.
//!
//! Run:
//! `cargo run --example custom_resolver -p affinidi-data-integrity`

use affinidi_data_integrity::{
    DataIntegrityError, DataIntegrityProof, DidKeyResolver, ResolvedKey, SignOptions,
    VerificationMethodResolver, VerifyOptions,
};
use affinidi_secrets_resolver::secrets::Secret;
use async_trait::async_trait;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Mutex;

/// Resolver that looks up DID verification methods in a local map.
/// A production implementation would instead fetch DID documents via
/// HTTP (did:web), a cache (did:webvh), or local storage (did:peer).
#[derive(Default)]
pub struct MapResolver {
    /// map<verification-method URI, (key_type, public_key_bytes)>
    entries: Mutex<HashMap<String, ResolvedKey>>,
}

impl MapResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, vm: String, key: ResolvedKey) {
        self.entries.lock().unwrap().insert(vm, key);
    }
}

#[async_trait]
impl VerificationMethodResolver for MapResolver {
    async fn resolve_vm(&self, vm: &str) -> Result<ResolvedKey, DataIntegrityError> {
        // In production: perform HTTP GET (did:web) or cache lookup
        // (did:webvh), parse the DID document, extract the matching
        // verification method, and decode its publicKeyMultibase /
        // publicKeyJwk. Return ResolvedKey { key_type, public_key_bytes }.
        //
        // Here: local map. Fall through to DidKeyResolver for did:key.
        if let Some(hit) = self.entries.lock().unwrap().get(vm) {
            return Ok(hit.clone());
        }
        // Chain to the built-in did:key handler so we still understand
        // did:key URIs without duplicating logic.
        DidKeyResolver.resolve_vm(vm).await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up a signer and register its verification method with the
    // custom resolver. In production the resolver would never need
    // to be told — it'd fetch DID documents on demand.
    let mut secret = Secret::generate_ed25519(None, Some(&[9u8; 32]));
    let pk_mb = secret.get_public_keymultibase()?;
    let vm = "did:web:example.com#key-0".to_string();
    secret.id = vm.clone();

    let resolver = MapResolver::new();
    resolver.insert(
        vm.clone(),
        ResolvedKey::new(
            affinidi_secrets_resolver::secrets::KeyType::Ed25519,
            secret.get_public_bytes().to_vec(),
        ),
    );

    // Sign and verify via the custom resolver.
    let doc = json!({"hello": "custom-resolver"});
    let proof = DataIntegrityProof::sign(&doc, &secret, SignOptions::new()).await?;
    proof.verify(&doc, &resolver, VerifyOptions::new()).await?;
    println!("Verified via custom MapResolver (registered did:web entry).");

    // The same resolver still handles did:key fallbacks.
    let did_key_secret =
        build_did_key_signer(Secret::generate_ed25519(None, Some(&[42u8; 32])), &pk_mb)?;
    let doc2 = json!({"hello": "did-key-fallback"});
    let proof2 = DataIntegrityProof::sign(&doc2, &did_key_secret, SignOptions::new()).await?;
    proof2
        .verify(&doc2, &resolver, VerifyOptions::new())
        .await?;
    println!("Verified a did:key proof via the same resolver (fallback to DidKeyResolver).");

    Ok(())
}

fn build_did_key_signer(mut s: Secret, _hint: &str) -> Result<Secret, Box<dyn std::error::Error>> {
    let pk_mb = s.get_public_keymultibase()?;
    s.id = format!("did:key:{pk_mb}#{pk_mb}");
    Ok(s)
}
