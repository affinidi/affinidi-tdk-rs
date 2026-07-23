//! `resolve_any()` — unified DID / agent name resolution and its two-level cache.
//!
//! These use an in-memory name backend rather than HTTP, so they exercise the
//! cache and verification wiring without a network. The HTTP redirect backend
//! itself is covered in the `agent-names` crate.

#![cfg(feature = "agent-names")]

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use affinidi_did_common::{Document, DocumentBuilder};
use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, config::DIDCacheConfigBuilder, errors::DIDCacheError,
};
use agent_names::{AgentName, AgentNameError, AgentNameResolver, NameResolution};

const NAME: &str = "example.com/@alice";
const CANONICAL: &str = "https://example.com/@alice";
/// `did:key` is *immutable*, so its document is cached with no expiry. That is
/// exactly what makes it the right DID for the TTL regression test below.
const IMMUTABLE_DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

/// A name backend backed by a fixed map, counting how often it is consulted.
struct MapResolver {
    map: HashMap<String, String>,
    calls: Arc<AtomicUsize>,
}

impl MapResolver {
    fn new(pairs: &[(&str, &str)]) -> (Self, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let map = pairs
            .iter()
            .map(|(n, d)| (n.to_string(), d.to_string()))
            .collect();
        (
            Self {
                map,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl AgentNameResolver for MapResolver {
    fn name(&self) -> &str {
        "test-map"
    }

    fn resolve<'a>(
        &'a self,
        name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            match self.map.get(name.as_str()) {
                Some(did) => Some(Ok(did.clone())),
                None => Some(Err(AgentNameError::Unresolvable(name.as_str().to_string()))),
            }
        })
    }
}

/// A document that claims `aka` via `alsoKnownAs`.
fn doc_claiming(did: &str, aka: &[&str]) -> Document {
    DocumentBuilder::new(did)
        .unwrap()
        .also_known_as_many(aka.iter().copied())
        .build()
}

/// Client with a seeded document cache and a map-backed name resolver.
async fn client_with(
    did: &str,
    aka: &[&str],
    pairs: &[(&str, &str)],
    name_ttl: u32,
) -> (DIDCacheClient, Arc<AtomicUsize>) {
    let config = DIDCacheConfigBuilder::default()
        .with_agent_name_ttl(name_ttl)
        .build();
    let mut client = DIDCacheClient::new(config).await.unwrap();

    let (resolver, calls) = MapResolver::new(pairs);
    client.set_agent_name_resolvers(vec![Box::new(resolver)]);
    // Seed the document cache so no real DID resolution happens.
    client.add_did_document(did, doc_claiming(did, aka)).await;

    (client, calls)
}

// --- pass-through ---

#[tokio::test]
async fn a_did_passes_straight_through() {
    let (client, calls) = client_with(IMMUTABLE_DID, &[], &[], 300).await;

    let response = client.resolve_any(IMMUTABLE_DID).await.unwrap();
    assert_eq!(response.did, IMMUTABLE_DID);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a DID must not consult the agent name backends"
    );
}

// --- happy path ---

#[tokio::test]
async fn resolves_an_agent_name_to_its_did() {
    let (client, calls) = client_with(
        IMMUTABLE_DID,
        &[CANONICAL],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;

    let response = client.resolve_any(NAME).await.unwrap();
    assert_eq!(
        response.did, IMMUTABLE_DID,
        "the response reports the resolved DID, not the name"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn accepts_a_scheme_less_also_known_as_entry() {
    let (client, _) = client_with(
        IMMUTABLE_DID,
        &["example.com/@alice"],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;
    assert!(client.resolve_any(NAME).await.is_ok());
}

/// All spellings of one name hit the same cache entry.
#[tokio::test]
async fn equivalent_spellings_share_one_mapping() {
    let (client, calls) = client_with(
        IMMUTABLE_DID,
        &[CANONICAL],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;

    for spelling in [
        "example.com/@alice",
        "https://example.com/@alice",
        "https://EXAMPLE.com/@alice",
        "https://example.com:443/@alice",
        "https://example.com/@alice/",
    ] {
        client.resolve_any(spelling).await.unwrap();
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "canonicalisation should collapse every spelling onto one cached mapping"
    );
}

// --- the mapping cache ---

#[tokio::test]
async fn a_cached_mapping_is_not_re_resolved() {
    let (client, calls) = client_with(
        IMMUTABLE_DID,
        &[CANONICAL],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;

    for _ in 0..5 {
        client.resolve_any(NAME).await.unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Resolving via the name warms the document cache for the bare DID too, so a
/// name and its DID never hold divergent copies of one document.
///
/// This deliberately does **not** pre-seed the document cache — that would make
/// the assertion vacuous, since resolving by DID would hit the seeded entry
/// whether or not the name path ran. Instead the name points at a real,
/// locally-resolvable `did:key`, whose generated document has no `alsoKnownAs`
/// and so fails Layer 1. The failure is the point: resolution still happened, so
/// the document must now be in the shared cache.
#[tokio::test]
async fn a_name_and_its_did_share_one_document_entry() {
    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await.unwrap();
    let (resolver, _) = MapResolver::new(&[(CANONICAL, IMMUTABLE_DID)]);
    client.set_agent_name_resolvers(vec![Box::new(resolver)]);

    // Nothing cached yet: resolving the DID directly is a miss.
    assert!(!client.resolve_any(IMMUTABLE_DID).await.unwrap().cache_hit);
    client.remove(IMMUTABLE_DID).await;

    // Resolve through the name. Verification fails (a did:key document claims no
    // names), but the underlying DID resolution still populated the cache.
    assert!(client.resolve_any(NAME).await.is_err());

    let by_did = client.resolve_any(IMMUTABLE_DID).await.unwrap();
    assert!(
        by_did.cache_hit,
        "resolving by name should have warmed the shared document cache for its DID"
    );
}

#[tokio::test]
async fn remove_agent_name_forces_re_resolution() {
    let (client, calls) = client_with(
        IMMUTABLE_DID,
        &[CANONICAL],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;

    client.resolve_any(NAME).await.unwrap();
    let name = AgentName::parse(NAME).unwrap();
    assert_eq!(
        client.remove_agent_name(&name).await.as_deref(),
        Some(IMMUTABLE_DID)
    );

    client.resolve_any(NAME).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// **Regression test for the `DIDExpiry` trap.**
///
/// `DIDExpiry` decides expiry from the *resolved document's* `id`, not from the
/// cache key. `did:key` is immutable, so its document is cached with **no**
/// expiry. Had the agent name been used as a key into that same cache, the
/// mapping would have inherited "never expires" — pinning a web redirect that
/// can change at any moment. The separate mapping cache must expire regardless.
#[tokio::test]
async fn a_mapping_to_an_immutable_did_still_expires() {
    let (client, calls) = client_with(
        IMMUTABLE_DID,
        &[CANONICAL],
        &[(CANONICAL, IMMUTABLE_DID)],
        1,
    )
    .await;

    client.resolve_any(NAME).await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_millis(1_500)).await;

    client.resolve_any(NAME).await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "the name->DID mapping must expire even though the DID it points at is immutable"
    );

    // …while the document itself stayed cached throughout.
    assert!(client.resolve_any(IMMUTABLE_DID).await.unwrap().cache_hit);
}

// --- Layer-1 verification ---

#[tokio::test]
async fn rejects_a_did_that_does_not_claim_the_name() {
    // The redirect points at a DID whose document says nothing about the name.
    let (client, _) = client_with(IMMUTABLE_DID, &[], &[(CANONICAL, IMMUTABLE_DID)], 300).await;

    let err = client.resolve_any(NAME).await.unwrap_err();
    assert!(
        matches!(err, DIDCacheError::AgentNameError(_)),
        "got {err:?}"
    );
    assert!(err.to_string().contains("alsoKnownAs"), "got {err}");
}

#[tokio::test]
async fn rejects_a_did_that_claims_a_different_name() {
    let (client, _) = client_with(
        IMMUTABLE_DID,
        &["https://example.com/@bob"],
        &[(CANONICAL, IMMUTABLE_DID)],
        300,
    )
    .await;
    assert!(client.resolve_any(NAME).await.is_err());
}

/// A failed verification must **evict** the mapping, so a poisoned entry is
/// re-fetched rather than re-failed from cache until its TTL happens to lapse.
#[tokio::test]
async fn failed_verification_evicts_the_mapping() {
    let (client, calls) = client_with(IMMUTABLE_DID, &[], &[(CANONICAL, IMMUTABLE_DID)], 300).await;

    assert!(client.resolve_any(NAME).await.is_err());
    assert!(client.resolve_any(NAME).await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "a rejected mapping must not stay cached"
    );

    let name = AgentName::parse(NAME).unwrap();
    assert_eq!(
        client.remove_agent_name(&name).await,
        None,
        "nothing should remain cached after a rejected verification"
    );
}

/// A mapping pointing at a DID that will not resolve must not stay cached for
/// the whole TTL — the next caller should re-ask the backend.
#[tokio::test]
async fn a_mapping_to_an_unresolvable_did_is_evicted() {
    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await.unwrap();
    let (resolver, calls) = MapResolver::new(&[(CANONICAL, "did:nosuchmethod:whatever")]);
    client.set_agent_name_resolvers(vec![Box::new(resolver)]);

    assert!(client.resolve_any(NAME).await.is_err());
    assert!(client.resolve_any(NAME).await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "an unresolvable mapping must be evicted, not cached"
    );
}

// --- backends ---

#[tokio::test]
async fn reports_an_unresolvable_name() {
    let (client, _) = client_with(IMMUTABLE_DID, &[CANONICAL], &[], 300).await;

    let err = client.resolve_any("example.com/@nobody").await.unwrap_err();
    assert!(
        matches!(err, DIDCacheError::AgentNameError(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn the_default_backend_is_http_redirect() {
    let config = DIDCacheConfigBuilder::default().build();
    let client = DIDCacheClient::new(config).await.unwrap();
    assert_eq!(client.agent_name_resolver_names(), ["http-redirect"]);
}

#[tokio::test]
async fn backends_are_tried_in_order() {
    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await.unwrap();

    let (first, _) = MapResolver::new(&[]);
    let (second, _) = MapResolver::new(&[]);
    client.set_agent_name_resolvers(vec![Box::new(first)]);
    client.append_agent_name_resolver(Box::new(second));
    assert_eq!(client.agent_name_resolver_names().len(), 2);
}

#[tokio::test]
async fn a_malformed_agent_name_is_rejected_before_any_lookup() {
    let (client, calls) = client_with(IMMUTABLE_DID, &[], &[], 300).await;

    // A community name takes no path, so this is malformed rather than a
    // context-qualified `example.com/@`.
    assert!(client.resolve_any("example.com/@/path").await.is_err());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a malformed name must not reach the backends"
    );
}

/// An email address has an `@` but no `/@`, so it is not mistaken for a name;
/// it falls through to DID parsing and is rejected there.
#[tokio::test]
async fn an_email_is_not_treated_as_an_agent_name() {
    let (client, calls) = client_with(IMMUTABLE_DID, &[], &[], 300).await;

    let err = client.resolve_any("alice@example.com").await.unwrap_err();
    assert!(matches!(err, DIDCacheError::DIDError(_)), "got {err:?}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// A backend that blocks until released, so several callers are provably
/// in-flight at the same moment.
struct GatedResolver {
    gate: Arc<tokio::sync::Notify>,
    calls: Arc<AtomicUsize>,
    did: String,
}

impl AgentNameResolver for GatedResolver {
    fn name(&self) -> &str {
        "gated"
    }

    fn resolve<'a>(
        &'a self,
        _name: &'a AgentName,
    ) -> Pin<Box<dyn Future<Output = NameResolution> + Send + 'a>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.gate.notified().await;
            Some(Ok(self.did.clone()))
        })
    }
}

/// Concurrent first-time lookups of the *same* name must make **one** backend
/// call, not one each.
///
/// This is the property that matters for a shared resolver: a name lookup is an
/// uncached fetch against somebody else's web server, so N concurrent callers
/// fanning out N requests is exactly what centralising resolution is meant to
/// avoid.
#[tokio::test]
async fn concurrent_lookups_of_one_name_resolve_exactly_once() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));

    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await.unwrap();
    client.set_agent_name_resolvers(vec![Box::new(GatedResolver {
        gate: gate.clone(),
        calls: calls.clone(),
        did: IMMUTABLE_DID.to_string(),
    })]);
    client
        .add_did_document(IMMUTABLE_DID, doc_claiming(IMMUTABLE_DID, &[CANONICAL]))
        .await;

    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = client.clone();
        handles.push(tokio::spawn(async move { c.resolve_any(NAME).await }));
    }

    // Let every task reach the backend (or block behind the leader), then
    // release the one that got through.
    tokio::time::sleep(Duration::from_millis(150)).await;
    gate.notify_waiters();

    for handle in handles {
        handle.await.unwrap().expect("every caller should resolve");
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "8 concurrent lookups of one name should make exactly one backend call"
    );
}

/// Different names must not block each other — the single-flight is per name,
/// not a global lock.
#[tokio::test]
async fn concurrent_lookups_of_different_names_do_not_serialise() {
    let (resolver, calls) = MapResolver::new(&[
        (CANONICAL, IMMUTABLE_DID),
        ("https://example.com/@bob", IMMUTABLE_DID),
    ]);

    let config = DIDCacheConfigBuilder::default().build();
    let mut client = DIDCacheClient::new(config).await.unwrap();
    client.set_agent_name_resolvers(vec![Box::new(resolver)]);
    client
        .add_did_document(
            IMMUTABLE_DID,
            doc_claiming(IMMUTABLE_DID, &[CANONICAL, "https://example.com/@bob"]),
        )
        .await;

    let (a, b) = tokio::join!(
        client.resolve_any("example.com/@alice"),
        client.resolve_any("example.com/@bob"),
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "two distinct names should each be resolved"
    );
}

/// A leader whose lookup FAILS must still wake its followers, and they must be
/// able to retry rather than hang.
#[tokio::test]
async fn a_failed_leader_does_not_strand_followers() {
    let (client, calls) = client_with(IMMUTABLE_DID, &[CANONICAL], &[], 300).await;

    let mut handles = Vec::new();
    for _ in 0..4 {
        let c = client.clone();
        handles.push(tokio::spawn(async move { c.resolve_any(NAME).await }));
    }

    for handle in handles {
        // The point is that these complete at all — a stranded follower would
        // hang here and fail the test by timeout.
        assert!(handle.await.unwrap().is_err());
    }
    assert!(
        calls.load(Ordering::SeqCst) >= 1,
        "at least one caller should have attempted resolution"
    );
}
