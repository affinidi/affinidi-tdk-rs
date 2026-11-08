//! The fetch path, exercised end to end against a live HTTP server.
//!
//! Every other test here verifies artifacts already in hand. These drive
//! `WebsResolver::resolve` itself — the URLs it actually requests, the order it
//! requests them in, what it does when one is missing, and the size caps — by
//! serving artifacts from a local server and resolving a DID that points at it.
//!
//! A DID resolves only at a host its AID designated, and the conformance
//! fixture designates its own host, not the mock's. The tests that need a
//! resolution to succeed therefore create an identifier for the mock's address
//! (and need the `create` feature); the failure paths use the fixture.

use affinidi_did_webs::{DidWebsError, HostPolicy, WebsResolver};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KERI_CESR: &[u8] = include_bytes!("fixtures/ENro7uf0.keri.cesr");
const DID_JSON: &[u8] = include_bytes!("fixtures/ENro7uf0.did.json");
const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";

/// A DID pointing at the mock server.
///
/// The mock listens on 127.0.0.1. Loopback is reachable only under
/// `HostPolicy::AllowPrivate`, which these tests use, and there the resolver
/// fetches it over plain HTTP — the same accommodation that lets it talk to
/// the reference implementation.
fn did_for(server: &MockServer) -> String {
    format!("did:webs:{}:{AID}", host_of(server))
}

/// The mock's address, as a `did:webs` host label.
fn host_of(server: &MockServer) -> String {
    server.address().to_string().replace(':', "%3A")
}

/// An identifier created for the mock's address, and its artifacts.
#[cfg(feature = "create")]
fn created_for(server: &MockServer) -> (String, String, affinidi_did_webs::Artifacts) {
    use affinidi_did_webs::create::{CreateConfig, create};
    use affinidi_keri::config::InceptionConfig;

    let result = create(
        CreateConfig::builder(host_of(server))
            .inception(InceptionConfig::builder().salt(vec![7u8; 16]).build())
            .build(),
    )
    .expect("create");
    let aid = affinidi_did_webs::DidWebs::parse(result.did())
        .expect("parse")
        .aid()
        .to_string();
    (result.did().to_string(), aid, result.into_artifacts())
}

async fn serve(server: &MockServer, artifact: &str, body: &[u8]) {
    serve_for(server, AID, artifact, body).await;
}

async fn serve_for(server: &MockServer, aid: &str, artifact: &str, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/{aid}/{artifact}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(server)
        .await;
}

#[cfg(feature = "create")]
#[tokio::test]
async fn resolves_a_did_over_the_network() {
    let server = MockServer::start().await;
    let (did, aid, artifacts) = created_for(&server);
    serve_for(&server, &aid, "keri.cesr", &artifacts.keri_cesr).await;
    serve_for(&server, &aid, "did.json", &artifacts.did_json).await;

    let resolution = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve_with_metadata(&did)
        .await
        .expect("a served did:webs must resolve");

    assert_eq!(resolution.document.id.as_str(), did);
    assert_eq!(resolution.document.verification_method.len(), 1);
    assert_eq!(resolution.metadata.version_id, 2);

    // Both artifacts were actually requested, at the paths we derive.
    let requests = server.received_requests().await.expect("recorded");
    let paths: Vec<String> = requests.iter().map(|r| r.url.path().to_string()).collect();
    assert!(paths.contains(&format!("/{aid}/keri.cesr")), "{paths:?}");
    assert!(paths.contains(&format!("/{aid}/did.json")), "{paths:?}");
}

#[cfg(feature = "create")]
#[tokio::test]
async fn a_version_id_resolves_an_earlier_document() {
    let server = MockServer::start().await;
    let (did, aid, artifacts) = created_for(&server);
    serve_for(&server, &aid, "keri.cesr", &artifacts.keri_cesr).await;
    serve_for(&server, &aid, "did.json", &artifacts.did_json).await;

    // At sequence number 1 the alias registry is anchored but not yet the
    // issuance, so the DID was not yet designated.
    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&format!("{did}?versionId=1"))
        .await
        .expect_err("not yet designated at sn 1");
    assert!(
        matches!(err, affinidi_did_webs::DidWebsError::NotDesignated(_)),
        "{err}"
    );
}

#[tokio::test]
async fn a_missing_did_json_fails_resolution() {
    // § Read: if either request fails, resolution fails. A host serving a log
    // but no document has not published the DID completely, and accepting it
    // would make the did.json cross-check optional for whoever runs the host.
    let server = MockServer::start().await;
    serve(&server, "keri.cesr", KERI_CESR).await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did_for(&server))
        .await
        .expect_err("a missing did.json must fail resolution");
    assert!(err.to_string().contains("did.json"), "{err}");
}

#[tokio::test]
async fn a_missing_keri_cesr_fails_resolution() {
    // The key event log is the only thing that carries authority, so its
    // absence is fatal — the opposite of did.json.
    let server = MockServer::start().await;
    serve(&server, "did.json", DID_JSON).await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did_for(&server))
        .await
        .expect_err("no key event log means no resolution");
    assert!(err.to_string().contains("keri.cesr"), "{err}");
}

#[tokio::test]
async fn a_server_error_is_surfaced_not_swallowed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{AID}/keri.cesr")))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did_for(&server))
        .await
        .expect_err("a 500 must fail resolution");
    assert!(err.to_string().contains("500"), "{err}");
}

#[tokio::test]
async fn an_oversized_artifact_is_refused() {
    // A key event log grows with every rotation and has no natural bound, and
    // the server is not trusted, so an artifact past the cap is refused rather
    // than read into memory.
    //
    // The body is genuinely oversized rather than merely claiming to be: hyper
    // will not serve a response whose Content-Length contradicts its body, so
    // a lying header cannot be tested this way.
    let oversized = vec![b'{'; 5 * 1024 * 1024];
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{AID}/keri.cesr")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(oversized))
        .mount(&server)
        .await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did_for(&server))
        .await
        .expect_err("an oversized artifact must be refused");
    assert!(err.to_string().contains("cap"), "{err}");
}

#[cfg(feature = "create")]
#[tokio::test]
async fn a_did_json_that_disagrees_fails_resolution() {
    // Served alongside a valid key event log, but publishing a key the log
    // never authorised. Resolution must fail rather than pick a winner.
    let server = MockServer::start().await;
    let (did, aid, artifacts) = created_for(&server);
    let mut published: serde_json::Value =
        serde_json::from_slice(&artifacts.did_json).expect("json");
    let mut extra = published["verificationMethod"][0].clone();
    extra["id"] = serde_json::json!("#DNotAuthorised000000000000000000000000000");
    extra["publicKeyJwk"]["kid"] = serde_json::json!("DNotAuthorised000000000000000000000000000");
    published["verificationMethod"]
        .as_array_mut()
        .expect("array")
        .push(extra);

    serve_for(&server, &aid, "keri.cesr", &artifacts.keri_cesr).await;
    serve_for(
        &server,
        &aid,
        "did.json",
        &serde_json::to_vec(&published).expect("serializes"),
    )
    .await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did)
        .await
        .expect_err("a did.json publishing an unauthorised key must fail resolution");
    assert!(
        err.to_string().contains("never authorised"),
        "should fail on the unauthorised key, got: {err}",
    );
}

#[tokio::test]
async fn a_non_loopback_host_is_fetched_over_https() {
    // The loopback accommodation must not leak into ordinary hosts: a DID on
    // a public host is fetched over HTTPS, so pointing one at a plain HTTP
    // server fails to connect rather than silently downgrading.
    let server = MockServer::start().await;
    serve(&server, "keri.cesr", KERI_CESR).await;

    // Same server, addressed through a non-loopback name.
    let port = server.address().port();
    let did = format!("did:webs:localtest.me%3A{port}:{AID}");

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did)
        .await
        .expect_err("a non-loopback host must not be fetched over plain HTTP");
    assert!(
        !err.to_string().contains("key event log verification"),
        "should have failed to fetch, not to verify: {err}",
    );
}

// -- host policy ----------------------------------------------------------

/// Under the default policy a DID naming a loopback, private, link-local or
/// special-use host is refused before any request is made: the DID names the
/// host, so otherwise anyone who can hand the resolver a DID can make it
/// fetch from inside the network it runs on.
#[tokio::test]
async fn the_default_policy_refuses_a_host_that_is_not_public() {
    let server = MockServer::start().await;
    serve(&server, "keri.cesr", KERI_CESR).await;
    serve(&server, "did.json", DID_JSON).await;

    for host in [
        host_of(&server),
        "localhost%3A8080".to_string(),
        "169.254.169.254".to_string(),
        "10.0.0.1".to_string(),
        "printer.local".to_string(),
        "did-webs-service%3A7676".to_string(),
    ] {
        let did = format!("did:webs:{host}:{AID}");
        let err = WebsResolver::new()
            .resolve(&did)
            .await
            .expect_err("a non-public host must be refused");
        assert!(matches!(err, DidWebsError::BlockedHost(_)), "{did}: {err}");
    }
    let requests = server.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the refused host was contacted: {requests:?}"
    );
}

/// A redirect is not followed: the DID names the host, and a 3xx would let it
/// send the resolver to an address the host check never saw.
#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    let target = MockServer::start().await;
    serve(&target, "keri.cesr", KERI_CESR).await;
    Mock::given(method("GET"))
        .and(path(format!("/{AID}/keri.cesr")))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}/{AID}/keri.cesr", target.uri())),
        )
        .mount(&server)
        .await;

    let err = WebsResolver::with_policy(HostPolicy::AllowPrivate)
        .resolve(&did_for(&server))
        .await
        .expect_err("a redirected artifact must not be fetched");
    assert!(err.to_string().contains("302"), "{err}");
    let requests = target.received_requests().await.expect("recorded");
    assert!(
        requests.is_empty(),
        "the redirect was followed: {requests:?}"
    );
}
