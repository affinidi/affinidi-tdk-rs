//! `CacheServerResolver` against a mock cache server.

use agent_names::{AgentName, AgentNameError, AgentNameResolver, CacheServerResolver};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const DID: &str = "did:webvh:QmScid:example.com";
const ROUTE: &str = "/did/v1/resolve-name/example.com/@alice";

async fn resolve(server: &MockServer, name: &str) -> Result<String, AgentNameError> {
    let resolver = CacheServerResolver::new(&server.uri()).unwrap();
    resolver
        .resolve(&AgentName::parse(name).unwrap())
        .await
        .expect("the cache-server backend always claims the name")
}

#[tokio::test]
async fn resolves_a_name_via_the_cache_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "name": "https://example.com/@alice",
            "did": DID,
        })))
        .mount(&server)
        .await;

    assert_eq!(resolve(&server, "example.com/@alice").await.unwrap(), DID);
}

/// The client sends the name scheme-less, so all spellings hit one route.
#[tokio::test]
async fn canonicalises_the_name_before_requesting() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "did": DID })))
        .mount(&server)
        .await;

    for spelling in [
        "example.com/@alice",
        "https://example.com/@alice",
        "https://EXAMPLE.com/@alice",
        "https://example.com:443/@alice",
        "https://example.com/@alice/",
    ] {
        assert_eq!(
            resolve(&server, spelling).await.unwrap(),
            DID,
            "spelling {spelling} should reach the same route"
        );
    }
}

#[tokio::test]
async fn surfaces_a_server_error_body() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(
            ResponseTemplate::new(502)
                .set_body_json(serde_json::json!({ "error": "upstream refused the redirect" })),
        )
        .mount(&server)
        .await;

    let err = resolve(&server, "example.com/@alice").await.unwrap_err();
    match err {
        AgentNameError::CacheServer {
            status, message, ..
        } => {
            assert_eq!(status, 502);
            assert!(message.contains("upstream refused"), "got {message}");
        }
        other => panic!("expected a CacheServer error, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_a_success_response_with_no_did() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(ROUTE))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({ "name": "whatever" })),
        )
        .mount(&server)
        .await;

    let err = resolve(&server, "example.com/@alice").await.unwrap_err();
    assert!(
        matches!(err, AgentNameError::CacheServer { .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn reports_a_404_from_a_server_without_the_endpoint() {
    // An older cache server, or one with `enable_agent_names = false`.
    let server = MockServer::start().await;
    let err = resolve(&server, "example.com/@alice").await.unwrap_err();
    match err {
        AgentNameError::CacheServer { status, .. } => assert_eq!(status, 404),
        other => panic!("expected a CacheServer error, got {other:?}"),
    }
}
