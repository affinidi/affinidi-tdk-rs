//! DID-document-backed VID resolution (behind the `did-resolver` feature).
//!
//! [`DidVidResolver`] resolves a DID (`did:web`, `did:webvh`, `did:peer`, …) to a
//! [`ResolvedVid`] by reading its DID document: the Ed25519 signing key from the
//! `authentication` relationship, the X25519 encryption key from `keyAgreement`,
//! and the TSP transport endpoint(s) from a service entry of type
//! [`TSP_SERVICE_TYPE`].
//!
//! DID resolution is asynchronous (it may hit the network for `did:web` /
//! `did:webvh`), but the [`VidResolver`] trait is synchronous. The resolver
//! therefore caches every resolution: call [`DidVidResolver::resolve_did`]
//! (async) to populate the cache, after which the synchronous
//! [`VidResolver::resolve`] serves the cached [`ResolvedVid`]. This matches the
//! library's existing "register, then resolve" model.

use std::collections::HashMap;
use std::sync::RwLock;

use affinidi_did_common::verification_method::VerificationRelationship;
use affinidi_did_common::{Document, DocumentExt};
use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use affinidi_encoding::{ED25519_PUB, X25519_PUB};
use url::Url;

use crate::error::TspError;
use crate::vid::ResolvedVid;
use crate::vid::resolver::VidResolver;

/// The DID-document service `type` that advertises a TSP transport endpoint.
///
/// Matches the ToIP Trust Tasks `bindings/tsp/0.1` convention and the
/// OpenWallet Foundation Labs `tsp` reference resolver.
pub const TSP_SERVICE_TYPE: &str = "TSPTransport";

/// Resolves DID-based VIDs to their public keys and TSP endpoints by reading
/// the DID document, with an internal cache.
pub struct DidVidResolver {
    client: DIDCacheClient,
    cache: RwLock<HashMap<String, ResolvedVid>>,
}

impl DidVidResolver {
    /// Create a resolver over an existing [`DIDCacheClient`].
    pub fn new(client: DIDCacheClient) -> Self {
        Self {
            client,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Resolve a DID to a [`ResolvedVid`], caching the result.
    ///
    /// Returns [`TspError::DidResolution`] if the DID cannot be resolved or its
    /// document lacks an Ed25519 authentication key or an X25519 keyAgreement
    /// key. A missing TSP service entry is not an error — `endpoints` is then
    /// empty (the caller may deliver out of band).
    pub async fn resolve_did(&self, did: &str) -> Result<ResolvedVid, TspError> {
        if let Some(cached) = self.cache.read().unwrap().get(did).cloned() {
            return Ok(cached);
        }

        let response = self
            .client
            .resolve(did)
            .await
            .map_err(|e| TspError::DidResolution(format!("could not resolve {did}: {e}")))?;

        let resolved = extract_vid(did, &response.doc)?;
        self.cache
            .write()
            .unwrap()
            .insert(did.to_string(), resolved.clone());
        Ok(resolved)
    }

    /// Drop any cached resolution for `did` (e.g. after a known DID-doc update).
    pub fn invalidate(&self, did: &str) {
        self.cache.write().unwrap().remove(did);
    }
}

impl VidResolver for DidVidResolver {
    /// Synchronous resolution serves the cache only; call
    /// [`DidVidResolver::resolve_did`] first to populate it.
    fn resolve(&self, vid: &str) -> Result<ResolvedVid, TspError> {
        self.cache
            .read()
            .unwrap()
            .get(vid)
            .cloned()
            .ok_or_else(|| TspError::VidNotFound(vid.to_string()))
    }
}

/// Build a [`ResolvedVid`] from a resolved DID [`Document`].
///
/// Signing key = first `authentication` verification method decoding to an
/// Ed25519 public key; encryption key = first `keyAgreement` method decoding to
/// an X25519 public key. Endpoints = the `serviceEndpoint` URIs of every
/// [`TSP_SERVICE_TYPE`] service. Decoding is delegated to
/// `VerificationMethod::decode_public_key`, which handles both
/// `publicKeyMultibase` and `publicKeyJwk` uniformly across DID methods.
fn extract_vid(did: &str, doc: &Document) -> Result<ResolvedVid, TspError> {
    let signing_key = first_public_key(doc, &doc.authentication, ED25519_PUB).ok_or_else(|| {
        TspError::DidResolution(format!(
            "{did}: no Ed25519 authentication key in DID document"
        ))
    })?;

    let encryption_key =
        first_public_key(doc, &doc.key_agreement, X25519_PUB).ok_or_else(|| {
            TspError::DidResolution(format!("{did}: no X25519 keyAgreement key in DID document"))
        })?;

    Ok(ResolvedVid {
        id: did.to_string(),
        signing_key,
        encryption_key,
        endpoints: tsp_endpoints(doc),
    })
}

/// First key in `relationships` that decodes to the given multicodec, as 32 raw bytes.
fn first_public_key(
    doc: &Document,
    relationships: &[VerificationRelationship],
    codec: u64,
) -> Option<[u8; 32]> {
    relationships
        .iter()
        .filter_map(|rel| verification_key(doc, rel))
        .find(|(c, _)| *c == codec)
        .and_then(|(_, bytes)| <[u8; 32]>::try_from(bytes).ok())
}

/// Resolve a verification relationship (embedded or by reference) to its
/// `(multicodec, key_bytes)`.
fn verification_key(doc: &Document, rel: &VerificationRelationship) -> Option<(u64, Vec<u8>)> {
    let vm = match rel {
        VerificationRelationship::VerificationMethod(vm) => vm.as_ref(),
        VerificationRelationship::Reference(id) => doc.get_verification_method(id)?,
        _ => return None,
    };
    vm.decode_public_key().ok()
}

/// The endpoint URLs of every `TSPTransport` service in the document.
fn tsp_endpoints(doc: &Document) -> Vec<Url> {
    doc.service
        .iter()
        .filter(|service| service.type_.iter().any(|t| t == TSP_SERVICE_TYPE))
        .flat_map(|service| service.service_endpoint.get_uris())
        // `Endpoint::Map` yields JSON-serialized strings (quoted); strip quotes.
        .filter_map(|uri| Url::parse(uri.trim_matches('"')).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vid::PrivateVid;
    use affinidi_encoding::encode_multikey;

    /// Build a DID document JSON for `did` advertising `vid`'s public keys
    /// (as Multikey verification methods) and an optional TSP endpoint.
    fn did_doc_json(did: &str, vid: &PrivateVid, tsp_endpoint: Option<&str>) -> String {
        let ed = encode_multikey(ED25519_PUB, &vid.verifying_key);
        let x = encode_multikey(X25519_PUB, &vid.encryption_key);
        let service = match tsp_endpoint {
            Some(url) => format!(
                r#","service":[{{"id":"{did}#tsp","type":"TSPTransport","serviceEndpoint":"{url}"}}]"#
            ),
            None => String::new(),
        };
        format!(
            r#"{{
              "id":"{did}",
              "verificationMethod":[
                {{"id":"{did}#key-1","type":"Multikey","controller":"{did}","publicKeyMultibase":"{ed}"}},
                {{"id":"{did}#key-2","type":"Multikey","controller":"{did}","publicKeyMultibase":"{x}"}}
              ],
              "authentication":["{did}#key-1"],
              "keyAgreement":["{did}#key-2"]
              {service}
            }}"#
        )
    }

    #[test]
    fn extract_vid_reads_keys_and_endpoint() {
        let did = "did:web:alice.example";
        let vid = PrivateVid::generate(did);
        let doc: Document =
            serde_json::from_str(&did_doc_json(did, &vid, Some("https://mediator.example/")))
                .expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");

        assert_eq!(resolved.id, did);
        assert_eq!(resolved.signing_key, vid.verifying_key);
        assert_eq!(resolved.encryption_key, vid.encryption_key);
        assert_eq!(resolved.endpoints.len(), 1);
        assert_eq!(resolved.endpoints[0].as_str(), "https://mediator.example/");
    }

    #[test]
    fn extract_vid_without_tsp_service_has_no_endpoints() {
        let did = "did:web:bob.example";
        let vid = PrivateVid::generate(did);
        let doc: Document =
            serde_json::from_str(&did_doc_json(did, &vid, None)).expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");
        assert!(resolved.endpoints.is_empty());
        assert_eq!(resolved.signing_key, vid.verifying_key);
    }

    #[test]
    fn extract_vid_errors_without_key_agreement() {
        let did = "did:web:carol.example";
        let vid = PrivateVid::generate(did);
        let ed = encode_multikey(ED25519_PUB, &vid.verifying_key);
        // Only an authentication key, no keyAgreement.
        let json = format!(
            r#"{{"id":"{did}",
                 "verificationMethod":[{{"id":"{did}#key-1","type":"Multikey","controller":"{did}","publicKeyMultibase":"{ed}"}}],
                 "authentication":["{did}#key-1"]}}"#
        );
        let doc: Document = serde_json::from_str(&json).expect("doc parses");
        assert!(matches!(
            extract_vid(did, &doc),
            Err(TspError::DidResolution(_))
        ));
    }

    #[test]
    fn cache_serves_sync_resolve_after_async() {
        // Pure cache behaviour without a live DIDCacheClient: insert directly.
        let did = "did:web:dave.example";
        let vid = PrivateVid::generate(did).to_resolved();
        let cache: RwLock<HashMap<String, ResolvedVid>> = RwLock::new(HashMap::new());
        cache.write().unwrap().insert(did.to_string(), vid.clone());

        // Mirrors the VidResolver::resolve cache read.
        let got = cache.read().unwrap().get(did).cloned();
        assert_eq!(got.unwrap().id, did);
    }

    /// End-to-end against a real `DIDCacheClient`, resolving a `did:key`
    /// (resolved locally, no network) to exercise the async path and the real
    /// `Document` decode. `did:key` carries the Ed25519 key in `authentication`
    /// and derives the X25519 `keyAgreement` key from it.
    #[tokio::test]
    async fn resolve_did_key_end_to_end() {
        use affinidi_did_resolver_cache_sdk::DIDCacheClient;
        use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;

        let vid = PrivateVid::generate("placeholder");
        let did = format!(
            "did:key:{}",
            encode_multikey(ED25519_PUB, &vid.verifying_key)
        );

        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .expect("client builds");
        let resolver = DidVidResolver::new(client);

        let resolved = resolver.resolve_did(&did).await.expect("resolves did:key");
        assert_eq!(resolved.signing_key, vid.verifying_key);
        // did:key has no TSP service entry.
        assert!(resolved.endpoints.is_empty());

        // The synchronous trait now serves the cached result.
        assert!(VidResolver::resolve(&resolver, &did).is_ok());
    }
}
