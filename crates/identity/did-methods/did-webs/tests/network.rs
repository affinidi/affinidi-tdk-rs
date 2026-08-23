//! The fetch path, exercised end to end against a live HTTP server.
//!
//! Every other test here verifies artifacts already in hand. These drive
//! `WebsResolver::resolve` itself — the URLs it actually requests, the order it
//! requests them in, what it does when one is missing, and the size caps — by
//! serving the real conformance artifacts from a local server and resolving a
//! DID that points at it.

use affinidi_did_webs::WebsResolver;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KERI_CESR: &[u8] = include_bytes!("fixtures/ENro7uf0.keri.cesr");
const DID_JSON: &[u8] = include_bytes!("fixtures/ENro7uf0.did.json");
const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const SIGNING_KEY: &str = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr";

/// A DID pointing at the mock server.
///
/// The mock listens on 127.0.0.1, which the resolver recognises as loopback
/// and therefore fetches over plain HTTP — the same accommodation that lets it
/// talk to the reference implementation.
fn did_for(server: &MockServer) -> String {
    let host = server.address().to_string().replace(':', "%3A");
    format!("did:webs:{host}:{AID}")
}

/// The fixture's `did.json` names the host it was published on, and the
/// host-binding check refuses it anywhere else — deliberately, so a document
/// cannot be lifted from one host and replayed at another. Retarget it at the
/// mock so the *rest* of the resolution is what these tests exercise.
fn did_json_for(server: &MockServer) -> serde_json::Value {
    let host = server.address().to_string().replace(':', "%3A");
    let mut doc: serde_json::Value = serde_json::from_slice(DID_JSON).expect("json");
    doc["id"] = serde_json::json!(format!("did:web:{host}:{AID}"));
    doc
}

async fn serve(server: &MockServer, artifact: &str, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path(format!("/{AID}/{artifact}")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn resolves_a_did_over_the_network() {
    let server = MockServer::start().await;
    serve(&server, "keri.cesr", KERI_CESR).await;
    let published = serde_json::to_vec(&did_json_for(&server)).expect("serializes");
    serve(&server, "did.json", &published).await;

    let did = did_for(&server);
    let doc = WebsResolver::new()
        .resolve(&did)
        .await
        .expect("a served did:webs must resolve");

    assert_eq!(doc.id.as_str(), did);
    assert_eq!(doc.verification_method.len(), 1);
    assert!(
        doc.verification_method[0]
            .id
            .as_str()
            .ends_with(&format!("#{SIGNING_KEY}")),
    );

    // Both artifacts were actually requested, at the paths we derive.
    let requests = server.received_requests().await.expect("recorded");
    let paths: Vec<String> = requests.iter().map(|r| r.url.path().to_string()).collect();
    assert!(paths.contains(&format!("/{AID}/keri.cesr")), "{paths:?}");
    assert!(paths.contains(&format!("/{AID}/did.json")), "{paths:?}");
}

#[tokio::test]
async fn resolves_when_did_json_is_missing() {
    // did.json carries no authority — it is only ever cross-checked. A 404 for
    // it must not stop resolution, because the key event log alone determines
    // the answer.
    let server = MockServer::start().await;
    serve(&server, "keri.cesr", KERI_CESR).await;

    let doc = WebsResolver::new()
        .resolve(&did_for(&server))
        .await
        .expect("a missing did.json must not fail resolution");
    assert_eq!(doc.verification_method.len(), 1);
}

#[tokio::test]
async fn a_missing_keri_cesr_fails_resolution() {
    // The key event log is the only thing that carries authority, so its
    // absence is fatal — the opposite of did.json.
    let server = MockServer::start().await;
    serve(&server, "did.json", DID_JSON).await;

    let err = WebsResolver::new()
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

    let err = WebsResolver::new()
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

    let err = WebsResolver::new()
        .resolve(&did_for(&server))
        .await
        .expect_err("an oversized artifact must be refused");
    assert!(err.to_string().contains("cap"), "{err}");
}

#[tokio::test]
async fn a_did_json_that_disagrees_fails_resolution() {
    // Served alongside a valid key event log, but publishing a key the log
    // never authorised. Resolution must fail rather than pick a winner.
    let server = MockServer::start().await;
    // Retargeted at this host, so the only thing wrong with it is the key.
    let mut published = did_json_for(&server);
    let mut extra = published["verificationMethod"][0].clone();
    extra["id"] = serde_json::json!("#DNotAuthorised000000000000000000000000000");
    extra["publicKeyJwk"]["kid"] = serde_json::json!("DNotAuthorised000000000000000000000000000");
    published["verificationMethod"]
        .as_array_mut()
        .expect("array")
        .push(extra);

    serve(&server, "keri.cesr", KERI_CESR).await;
    serve(
        &server,
        "did.json",
        &serde_json::to_vec(&published).expect("serializes"),
    )
    .await;

    let err = WebsResolver::new()
        .resolve(&did_for(&server))
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

    let err = WebsResolver::new()
        .resolve(&did)
        .await
        .expect_err("a non-loopback host must not be fetched over plain HTTP");
    assert!(
        !err.to_string().contains("key event log verification"),
        "should have failed to fetch, not to verify: {err}",
    );
}
