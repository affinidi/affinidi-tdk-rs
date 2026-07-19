//! End-to-end resolution against a mock web server.
//!
//! These cover the parts that unit tests cannot: that redirects are actually
//! followed, that the hop cap and HTTPS policy are enforced on every hop, and
//! that a non-redirecting name fails rather than hanging or guessing.

use agent_names::{AgentName, AgentNameError, AgentNameResolver, HttpRedirectResolver};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

const DID: &str = "did:webvh:QmScid:example.com";

/// The mock server speaks plain HTTP, so the resolver must opt into it.
fn resolver() -> HttpRedirectResolver {
    HttpRedirectResolver::new().allow_insecure_http(true)
}

fn name_for(server: &MockServer, local: &str) -> AgentName {
    AgentName::parse(&format!("{}/@{local}", server.uri())).unwrap()
}

async fn resolve(r: &HttpRedirectResolver, n: &AgentName) -> Result<String, AgentNameError> {
    r.resolve(n)
        .await
        .expect("http-redirect backend always claims the name")
}

#[tokio::test]
async fn resolves_a_bare_did_in_the_location_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", DID))
        .mount(&server)
        .await;

    let did = resolve(&resolver(), &name_for(&server, "alice"))
        .await
        .unwrap();
    assert_eq!(did, DID);
}

/// The FAQ does not pin the status code, so accept the whole 3xx family.
#[tokio::test]
async fn accepts_every_redirect_status() {
    for status in [301u16, 302, 303, 307, 308] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/@alice"))
            .respond_with(ResponseTemplate::new(status).insert_header("location", DID))
            .mount(&server)
            .await;

        let did = resolve(&resolver(), &name_for(&server, "alice"))
            .await
            .unwrap_or_else(|e| panic!("status {status} should resolve, got {e}"));
        assert_eq!(did, DID, "status {status}");
    }
}

#[tokio::test]
async fn resolves_a_did_carried_in_a_query_parameter() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("https://resolver.example/r?did={DID}").as_str(),
        ))
        .mount(&server)
        .await;

    let did = resolve(&resolver(), &name_for(&server, "alice"))
        .await
        .unwrap();
    assert_eq!(did, DID);
}

/// An apex->www hop on the way to the DID must not break resolution.
#[tokio::test]
async fn follows_an_intermediate_non_did_redirect() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "/canonical/@alice"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/canonical/@alice"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", DID))
        .mount(&server)
        .await;

    let did = resolve(&resolver(), &name_for(&server, "alice"))
        .await
        .unwrap();
    assert_eq!(did, DID);
}

#[tokio::test]
async fn rejects_a_name_that_does_not_redirect() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(200).set_body_string("a normal web page"))
        .mount(&server)
        .await;

    let err = resolve(&resolver(), &name_for(&server, "alice"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::NoRedirect { status: 200, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_a_404() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@nobody"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = resolve(&resolver(), &name_for(&server, "nobody"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::NoRedirect { status: 404, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_a_redirect_loop() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@loop"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/@loop"))
        .mount(&server)
        .await;

    let err = resolve(&resolver().with_max_hops(3), &name_for(&server, "loop"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::TooManyRedirects { limit: 3, .. }),
        "got {err:?}"
    );
}

#[tokio::test]
async fn rejects_a_redirect_with_no_location_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(302))
        .mount(&server)
        .await;

    let err = resolve(&resolver(), &name_for(&server, "alice"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::NoRedirect { .. }),
        "got {err:?}"
    );
}

/// Plain HTTP must be refused unless explicitly opted into.
#[tokio::test]
async fn refuses_plain_http_by_default() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", DID))
        .mount(&server)
        .await;

    let err = resolve(&HttpRedirectResolver::new(), &name_for(&server, "alice"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::InsecureScheme(_)),
        "got {err:?}"
    );
}

// NOTE: the mid-chain HTTPS downgrade check (`resolver.rs`, the per-hop scheme
// test) is NOT covered here. Exercising it needs an entry point over real HTTPS
// that then redirects to `http://`, and `wiremock` serves plain HTTP only — with
// a single `allow_insecure_http` flag, a plain-HTTP mock either allows every hop
// or refuses the first one, so any test written against it would pass for the
// wrong reason. Covering this properly needs a TLS-capable mock server.

#[tokio::test]
async fn honours_a_custom_hop_cap_of_one() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/@alice"))
        .respond_with(ResponseTemplate::new(301).insert_header("location", "/hop/@alice"))
        .mount(&server)
        .await;

    let err = resolve(&resolver().with_max_hops(1), &name_for(&server, "alice"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, AgentNameError::TooManyRedirects { limit: 1, .. }),
        "got {err:?}"
    );
}
