//! End-to-end lifecycle tests for the test mediator fixture.
//!
//! These tests exercise the externally observable surface of a running
//! mediator: HTTP endpoints reachable, identities issued, multiple
//! instances can coexist, graceful shutdown completes. They are not
//! exhaustive protocol-level tests — those live alongside the routing
//! and authentication code.
//!
//! Each Redis-touching test calls `skip_if_no_redis()` so the suite
//! degrades cleanly on machines without Redis. Once `MemoryStore`
//! lands (commit 11) the gate disappears.

mod common;

use std::time::Duration;

use affinidi_messaging_test_mediator::{TestEnvironment, TestMediator};
use common::{init_tracing, skip_if_no_redis};

/// Smoke test: spawning and shutting down a mediator runs to
/// completion without panics or hangs.
#[tokio::test]
async fn spawn_and_shutdown_round_trip() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("test mediator spawn");

    // Sanity-check the handle has the data we expect.
    assert_eq!(mediator.endpoint().scheme(), "http");
    assert!(mediator.did().starts_with("did:peer:2."));
    assert!(!mediator.admin_did().is_empty());
    assert!(mediator.bound_addr().port() > 0);

    mediator.shutdown();
    mediator
        .join()
        .await
        .expect("mediator joins cleanly after shutdown");
}

/// Each `add_user` call mints a fresh `did:peer` distinct from prior
/// users and from the mediator itself. Catches any accidental key
/// reuse in the fixture.
#[tokio::test]
async fn add_user_creates_distinct_dids() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("env spawn");

    let alice = env.add_user("Alice").await.expect("add Alice");
    let bob = env.add_user("Bob").await.expect("add Bob");

    assert!(alice.did.starts_with("did:peer:2."));
    assert!(bob.did.starts_with("did:peer:2."));
    assert_ne!(alice.did, bob.did, "Alice and Bob must have distinct DIDs");
    assert_ne!(
        alice.did,
        env.mediator.did(),
        "users and mediator must have distinct DIDs"
    );
    assert_eq!(alice.alias, "Alice");
    assert_eq!(bob.alias, "Bob");
    assert_eq!(alice.secrets.len(), 2, "Ed25519 + X25519 = 2 secrets");
    assert_eq!(bob.secrets.len(), 2);

    env.shutdown().await.expect("env shutdown");
}

/// `TestMediator::with_users` returns the handle plus one user per
/// alias, in order, each with a distinct `did:peer` and key material
/// already registered on the mediator. This is the non-ATM consumer
/// shortcut for the routing-2.0 wiring.
#[tokio::test]
async fn with_users_returns_pre_registered_participants() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let (mediator, users) = TestMediator::with_users(["alice", "bob"])
        .await
        .expect("with_users");

    assert_eq!(users.len(), 2);
    assert_eq!(users[0].alias, "alice");
    assert_eq!(users[1].alias, "bob");
    assert!(users[0].did.starts_with("did:peer:2."));
    assert!(users[1].did.starts_with("did:peer:2."));
    assert_ne!(users[0].did, users[1].did);
    assert_eq!(users[0].secrets.len(), 2);
    assert_eq!(users[1].secrets.len(), 2);

    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

/// `register_local_did` is idempotent: calling it twice with the same
/// DID does not error. Guards against accidental panics or duplicate
/// account-creation failures when callers register defensively.
#[tokio::test]
async fn register_local_did_is_idempotent() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let alice = mediator.add_user("alice").await.expect("add alice");

    // Re-registering the same DID must succeed silently.
    mediator
        .register_local_did(&alice.did)
        .await
        .expect("re-register alice");

    mediator.shutdown();
    mediator.join().await.expect("mediator joins");
}

/// `/healthchecker` answers without authentication. This is the most
/// minimal "the HTTP server is up" probe.
#[tokio::test]
async fn mediator_serves_healthchecker() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}healthchecker", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let resp = client
        .get(&url)
        .send()
        .await
        .expect("healthchecker request");
    assert!(
        resp.status().is_success(),
        "healthchecker status: {}",
        resp.status()
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `/readyz` returns a structured response covering Redis connectivity,
/// circuit breaker state, queue depth, and load shedding. We don't
/// assert the exact payload — only that the endpoint is reachable and
/// returns either 200 (healthy) or 503 (one of its checks failed).
#[tokio::test]
async fn mediator_serves_readyz() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = format!("{}readyz", mediator.endpoint());

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");

    let resp = client.get(&url).send().await.expect("readyz request");
    let status = resp.status().as_u16();
    assert!(
        status == 200 || status == 503,
        "readyz returned unexpected status: {status}"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// The bound URL on the handle reflects the listener's actual port —
/// not the requested `:0`. Connecting to the URL must succeed.
#[tokio::test]
async fn bound_url_reflects_actual_listener() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let url = mediator.endpoint().clone();
    let bound = mediator.bound_addr();

    assert_ne!(bound.port(), 0, "OS-assigned port must be non-zero");
    assert_eq!(
        url.host_str(),
        Some(&bound.ip().to_string() as &str),
        "endpoint host must match bound listener IP"
    );
    assert_eq!(
        url.port(),
        Some(bound.port()),
        "endpoint port must match bound listener port"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Two simultaneously running mediators each get their own ephemeral
/// port. Verifies isolation when a single test process spawns multiple
/// fixtures (parallel test orchestration, multi-mediator scenarios).
#[tokio::test]
async fn parallel_mediators_use_distinct_ports() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let m1 = TestMediator::spawn().await.expect("spawn first mediator");
    let m2 = TestMediator::spawn().await.expect("spawn second mediator");

    assert_ne!(
        m1.bound_addr().port(),
        m2.bound_addr().port(),
        "two test mediators must bind to different ports"
    );
    assert_ne!(
        m1.did(),
        m2.did(),
        "two test mediators must have distinct DIDs"
    );

    m1.shutdown();
    m2.shutdown();
    let _ = m1.join().await;
    let _ = m2.join().await;
}

/// `TestEnvironment` exposes the mediator handle, TDK state, and SDK
/// client all together. Verify the SDK got configured with the
/// mediator's DID by checking that adding a user resolves the
/// mediator pointer through the SDK's profile registration.
#[tokio::test]
async fn environment_wires_sdk_profile_to_mediator() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let env = TestEnvironment::spawn().await.expect("env spawn");
    let alice = env.add_user("Alice").await.expect("add Alice");

    // The user's profile should report the mediator's DID via `dids()`.
    let (profile_did, mediator_did) = alice
        .profile
        .dids()
        .expect("profile has mediator configured");
    assert_eq!(profile_did, alice.did);
    assert_eq!(mediator_did, env.mediator.did());

    env.shutdown().await.expect("env shutdown");
}

/// Resolve `did` and return the URI of its first DIDCommMessaging service.
/// The `did:peer:2` representation produced by the test-mediator stores the
/// URI inside `service_endpoint` as a JSON map with a `uri` key (the long
/// form of the peer-DID service block).
///
/// Inspects the resolved Document via JSON serialization rather than
/// importing `affinidi_did_common::service::Endpoint`, so the test crate
/// doesn't need a fresh dev-dependency just to peek at one field.
async fn resolve_didcomm_service_uri(did: &str) -> Option<String> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .expect("DID resolver");
    let resolved = resolver.resolve(did).await.expect("resolve user DID");

    let doc = serde_json::to_value(&resolved.doc).expect("serialize Document");
    let services = doc.get("service")?.as_array()?;
    for service in services {
        // Filter on type — DID-Doc service types can be a string or an array
        let type_field = service.get("type")?;
        let is_didcomm = match type_field {
            serde_json::Value::String(s) => s == "DIDCommMessaging",
            serde_json::Value::Array(arr) => {
                arr.iter().any(|v| v.as_str() == Some("DIDCommMessaging"))
            }
            _ => false,
        };
        if !is_didcomm {
            continue;
        }
        let endpoint = service.get("serviceEndpoint")?;
        // Endpoint may be a plain URL string, an object with `uri`, or
        // an array of either. Peel the first URI we find.
        let candidates: Vec<&serde_json::Value> = match endpoint {
            serde_json::Value::Array(arr) => arr.iter().collect(),
            other => vec![other],
        };
        for c in candidates {
            if let Some(s) = c.as_str() {
                return Some(s.to_string());
            }
            if let Some(uri) = c.get("uri").and_then(|v| v.as_str()) {
                return Some(uri.to_string());
            }
        }
    }
    None
}

/// `add_user` mints a `did:peer:2` whose DIDCommMessaging service URI is
/// the mediator's DID. This is the architectural contract the routing-2.0
/// self-loopback path relies on — without it, the routing handler would
/// classify the user's next-hop as remote and push the forward onto the
/// remote-delivery queue.
#[tokio::test]
async fn add_user_dids_have_mediator_did_as_service_uri() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::spawn().await.expect("spawn");
    let alice = mediator.add_user("alice").await.expect("add alice");

    let uri = resolve_didcomm_service_uri(&alice.did)
        .await
        .expect("alice's DID has a DIDCommMessaging service URI");
    assert_eq!(
        uri,
        mediator.did(),
        "minted user DID must point at the mediator's DID, not its HTTP URL"
    );

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// Same contract for `with_users`. The two paths share an
/// implementation today but the assertion guards against drift.
#[tokio::test]
async fn with_users_dids_have_mediator_did_as_service_uri() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let (mediator, users) = TestMediator::with_users(["alice", "bob"])
        .await
        .expect("with_users");

    for user in &users {
        let uri = resolve_didcomm_service_uri(&user.did)
            .await
            .unwrap_or_else(|| panic!("{} has no DIDCommMessaging service URI", user.alias));
        assert_eq!(
            uri,
            mediator.did(),
            "{}'s DID must point at the mediator's DID",
            user.alias
        );
    }

    mediator.shutdown();
    let _ = mediator.join().await;
}

/// `enable_external_forwarding(false)` is honored by the builder and
/// produces a working mediator. With external forwarding off, the
/// routing handler delivers every forward locally regardless of the
/// next-hop's DID Document — which is what tests want when their user
/// DIDs were minted with the mediator's HTTP URL (rather than its DID)
/// as the service endpoint.
///
/// This test only verifies the builder/spawn surface; the actual
/// "routes locally" behavior is covered by routing.rs unit tests and
/// the SDK's e2e suite. Adding a true round-trip assertion (alice
/// forwards to bob, bob receives) is tracked as followup.
#[tokio::test]
async fn enable_external_forwarding_disabled_spawns_successfully() {
    init_tracing();
    if skip_if_no_redis() {
        return;
    }

    let mediator = TestMediator::builder()
        .enable_forwarding(true)
        .enable_external_forwarding(false)
        .spawn()
        .await
        .expect("spawn with external forwarding disabled");

    // Sanity: handle is fully populated and the mediator answers HTTP.
    assert!(mediator.bound_addr().port() > 0);
    let url = format!("{}healthchecker", mediator.endpoint());
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("reqwest client");
    let resp = client.get(&url).send().await.expect("healthchecker");
    assert!(resp.status().is_success());

    mediator.shutdown();
    let _ = mediator.join().await;
}
