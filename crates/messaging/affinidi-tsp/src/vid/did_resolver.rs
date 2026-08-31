//! DID-document-backed VID resolution (behind the `did-resolver` feature).
//!
//! [`DidVidResolver`] resolves a DID (`did:web`, `did:webvh`, `did:peer`, …) to a
//! [`ResolvedVid`] by reading its DID document: the Ed25519 signing key from the
//! `authentication` relationship, the X25519 encryption key from `keyAgreement`,
//! and the TSP transport advertisement from a service entry of type
//! [`TSP_SERVICE_TYPE`].
//!
//! That last one has two shapes, and they are kept apart. A `TSPTransport`
//! `serviceEndpoint` either names a transport URL (`endpoints`) or names the DID
//! of the mediator that carries this VID's traffic (`mediators`), whose own
//! document holds the URL. Both are legitimate; only the first is something a
//! transport can connect to.
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
    /// key. A missing TSP service entry is not an error — `endpoints` and
    /// `mediators` are then both empty (the caller may deliver out of band).
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
/// an X25519 public key. The `serviceEndpoint` of every [`TSP_SERVICE_TYPE`]
/// service is split by [`tsp_endpoints`] into transport URLs (`endpoints`) and
/// mediator DIDs (`mediators`). Decoding is delegated to
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

    let services = tsp_endpoints(doc);
    Ok(ResolvedVid {
        id: did.to_string(),
        signing_key,
        encryption_key,
        endpoints: services.urls,
        mediators: services.mediators,
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

/// Every `TSPTransport` `serviceEndpoint` in the document, split by what it
/// actually names: a transport URL, or the DID of the mediator that carries this
/// VID's traffic.
#[derive(Debug, Default)]
struct TspServices {
    /// HTTP-family URLs a sender can connect to directly.
    urls: Vec<Url>,
    /// DIDs naming a mediator; the transport URL is in *that* document.
    mediators: Vec<String>,
}

/// Split the `TSPTransport` service endpoints of `doc` into transport URLs and
/// mediator DIDs.
///
/// The scheme test is the point of this function. `did:` is a perfectly valid
/// URL scheme, so `Url::parse("did:webvh:…")` succeeds and a DID-valued endpoint
/// used to arrive in `endpoints` indistinguishable from a real transport URL —
/// and then travelled all the way to the HTTP client, which failed to build a
/// request from it. A DID here is legitimate data (it says "I am mediated"), so
/// it is kept, just not as something to connect to.
///
/// Only the HTTP family is admitted as a URL: `/inbound` is appended to these,
/// and any other scheme is something this library has no delivery rule for.
fn tsp_endpoints(doc: &Document) -> TspServices {
    let mut out = TspServices::default();
    for uri in doc
        .service
        .iter()
        .filter(|service| service.type_.iter().any(|t| t == TSP_SERVICE_TYPE))
        .flat_map(|service| service.service_endpoint.get_uris())
    {
        // `Endpoint::Map` yields JSON-serialized strings (quoted); strip quotes.
        let uri = uri.trim_matches('"');
        if uri.starts_with("did:") {
            out.mediators.push(uri.to_string());
            continue;
        }
        if let Ok(url) = Url::parse(uri)
            && matches!(url.scheme(), "http" | "https" | "ws" | "wss")
        {
            out.urls.push(url);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vid::PrivateVid;
    use affinidi_encoding::encode_multikey;

    /// Build a DID document JSON for `did` advertising `vid`'s public keys
    /// (as Multikey verification methods) and an optional TSP endpoint.
    fn did_doc_json(did: &str, vid: &PrivateVid, tsp_endpoint: Option<&str>) -> String {
        did_doc_json_multi(did, vid, tsp_endpoint.as_slice())
    }

    /// As [`did_doc_json`], but with any number of `TSPTransport` services — the
    /// document order of `tsp_endpoints` is what the splitting tests assert on.
    fn did_doc_json_multi(did: &str, vid: &PrivateVid, tsp_endpoints: &[&str]) -> String {
        let ed = encode_multikey(ED25519_PUB, &vid.verifying_key);
        let x = encode_multikey(X25519_PUB, &vid.encryption_key);
        let service = if tsp_endpoints.is_empty() {
            String::new()
        } else {
            let entries = tsp_endpoints
                .iter()
                .enumerate()
                .map(|(i, url)| {
                    format!(
                        r#"{{"id":"{did}#tsp-{i}","type":"TSPTransport","serviceEndpoint":"{url}"}}"#
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!(r#","service":[{entries}]"#)
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

    /// The production shape this split exists for: a persona document whose
    /// `#tsp` service names its **mediator by DID**, not a URL. `did:` parses as
    /// a URL (scheme `did`, cannot-be-a-base), so before the scheme test this
    /// landed in `endpoints` and was handed to the HTTP client verbatim.
    #[test]
    fn a_did_valued_tsp_endpoint_is_a_mediator_not_an_endpoint() {
        let did = "did:web:persona.example";
        let mediator = "did:webvh:QmbHZC8JUpUD1XrdEcNiAPTxke4WpDyBPjjigPpEwYZiq5:dids.firstperson.dev:firstperson-mediator";
        let vid = PrivateVid::generate(did);
        let doc: Document =
            serde_json::from_str(&did_doc_json(did, &vid, Some(mediator))).expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");

        assert!(
            resolved.endpoints.is_empty(),
            "a DID is not a transport URL and must not appear as one"
        );
        assert_eq!(resolved.mediators, vec![mediator.to_string()]);
        assert!(
            resolved.advertises_tsp(),
            "a mediated VID still advertises TSP — dropping the DID silently would read as 'no TSP'"
        );
    }

    /// A document may publish both; each lands in its own bucket, in document
    /// order.
    #[test]
    fn urls_and_mediator_dids_are_split_not_merged() {
        let did = "did:web:both.example";
        let vid = PrivateVid::generate(did);
        let doc: Document = serde_json::from_str(&did_doc_json_multi(
            did,
            &vid,
            &["did:web:mediator.example", "https://direct.example/v1"],
        ))
        .expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");

        assert_eq!(
            resolved
                .endpoints
                .iter()
                .map(Url::as_str)
                .collect::<Vec<_>>(),
            vec!["https://direct.example/v1"]
        );
        assert_eq!(
            resolved.mediators,
            vec!["did:web:mediator.example".to_string()]
        );
    }

    /// Neither a DID nor an HTTP-family URL: no delivery rule, so it is dropped
    /// rather than passed on as an endpoint the transport would choke on.
    #[test]
    fn a_non_http_non_did_endpoint_is_dropped() {
        let did = "did:web:odd.example";
        let vid = PrivateVid::generate(did);
        let doc: Document =
            serde_json::from_str(&did_doc_json(did, &vid, Some("mailto:ops@odd.example")))
                .expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");

        assert!(resolved.endpoints.is_empty());
        assert!(resolved.mediators.is_empty());
        assert!(!resolved.advertises_tsp());
    }

    /// `ws://` is admitted alongside `http(s)://` — the mediator's own DID
    /// document advertises a WebSocket transport next to its HTTP one.
    #[test]
    fn websocket_endpoints_are_transport_urls() {
        let did = "did:web:ws.example";
        let vid = PrivateVid::generate(did);
        let doc: Document = serde_json::from_str(&did_doc_json(
            did,
            &vid,
            Some("wss://ws.example/mediator/v1/ws"),
        ))
        .expect("doc parses");

        let resolved = extract_vid(did, &doc).expect("extracts");

        assert_eq!(resolved.endpoints.len(), 1);
        assert!(resolved.mediators.is_empty());
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
