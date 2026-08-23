//! Resolving a real `did:webs` identifier from its published artifacts.
//!
//! These bytes were produced by keripy, not by this workspace, so this is the
//! only test here that can catch us agreeing with ourselves instead of with the
//! ecosystem. See `tests/fixtures/ATTRIBUTION.md`.

use affinidi_did_webs::{DidWebs, resolve_from_artifacts};

const KERI_CESR: &[u8] = include_bytes!("fixtures/ENro7uf0.keri.cesr");
const DID_JSON: &[u8] = include_bytes!("fixtures/ENro7uf0.did.json");

const AID: &str = "ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe";
const SIGNING_KEY: &str = "DHr0-I-mMN7h6cLMOTRJkkfPuMd0vgQPrOk4Y3edaHjr";

fn did() -> DidWebs {
    DidWebs::parse(&format!("did:webs:did-webs-service%3a7676:{AID}")).expect("valid did")
}

#[test]
fn resolves_a_real_identifier() {
    let doc = resolve_from_artifacts(&did(), KERI_CESR, Some(DID_JSON))
        .expect("a real did:webs artifact must resolve");

    assert_eq!(
        doc.id.as_str(),
        format!("did:webs:did-webs-service%3a7676:{AID}"),
        "the resolved document is for the DID asked about",
    );

    assert_eq!(doc.verification_method.len(), 1);
    let vm = &doc.verification_method[0];
    assert_eq!(vm.type_, "JsonWebKey");
    assert!(vm.id.as_str().ends_with(&format!("#{SIGNING_KEY}")));

    let jwk = vm.property_set.get("publicKeyJwk").expect("has a jwk");
    // The published did.json carries exactly this key material.
    assert_eq!(jwk["crv"], "Ed25519");
    assert_eq!(jwk["x"], "evT4j6Yw3uHpwsw5NEmSR8-4x3S-BA-s6Thjd51oeOs");
}

#[test]
fn resolves_without_the_published_document() {
    // did.json carries no authority: resolution must succeed on the key event
    // log alone, and produce the same answer.
    let with = resolve_from_artifacts(&did(), KERI_CESR, Some(DID_JSON)).expect("resolves");
    let without = resolve_from_artifacts(&did(), KERI_CESR, None).expect("resolves");
    assert_eq!(
        serde_json::to_value(&with).expect("serializes"),
        serde_json::to_value(&without).expect("serializes"),
        "did.json must not change what is resolved",
    );
}

#[test]
fn a_did_json_publishing_an_unauthorised_key_is_rejected() {
    // The case that matters: a document served alongside a valid KEL, but
    // naming a key the KEL never established. Accepting it would hand a caller
    // an attacker's key with the KEL's authority behind it.
    // Keep the real key and *add* one, so this tests the extra key
    // specifically rather than also tripping the missing-key check.
    let mut published: serde_json::Value = serde_json::from_slice(DID_JSON).expect("valid json");
    let mut extra = published["verificationMethod"][0].clone();
    extra["id"] = serde_json::json!("#DNotTheKeyTheKelAuthorised0000000000000000");
    extra["publicKeyJwk"]["kid"] = serde_json::json!("DNotTheKeyTheKelAuthorised0000000000000000");
    published["verificationMethod"]
        .as_array_mut()
        .expect("array")
        .push(extra);

    let bytes = serde_json::to_vec(&published).expect("serializes");
    let err = resolve_from_artifacts(&did(), KERI_CESR, Some(&bytes))
        .expect_err("an unauthorised published key must fail resolution");
    assert!(err.to_string().contains("never authorised"), "{err}");
}

#[test]
fn a_did_json_missing_an_authorised_key_is_rejected() {
    let mut published: serde_json::Value = serde_json::from_slice(DID_JSON).expect("valid json");
    published["verificationMethod"] = serde_json::json!([]);

    let bytes = serde_json::to_vec(&published).expect("serializes");
    let err = resolve_from_artifacts(&did(), KERI_CESR, Some(&bytes))
        .expect_err("a document omitting an authorised key must fail resolution");
    assert!(err.to_string().contains("does not publish"), "{err}");
}

#[test]
fn a_did_json_for_another_identifier_is_rejected() {
    let mut published: serde_json::Value = serde_json::from_slice(DID_JSON).expect("valid json");
    published["id"] = serde_json::json!("did:web:example.com:ESomeoneElse");

    let bytes = serde_json::to_vec(&published).expect("serializes");
    assert!(resolve_from_artifacts(&did(), KERI_CESR, Some(&bytes)).is_err());
}

#[test]
fn the_published_did_web_twin_id_is_accepted() {
    // The real did.json's `id` is the did:web form, because the document is
    // shared with the twin at the same URL. Rejecting that would fail every
    // real artifact.
    let published: serde_json::Value = serde_json::from_slice(DID_JSON).expect("valid json");
    assert_eq!(
        published["id"].as_str(),
        Some(format!("did:web:did-webs-service%3a7676:{AID}").as_str()),
        "fixture sanity: the published id really is the did:web twin",
    );
    assert!(resolve_from_artifacts(&did(), KERI_CESR, Some(DID_JSON)).is_ok());
}

#[test]
fn a_tampered_key_event_log_is_rejected() {
    // Flip a byte inside the inception event. Its SAID no longer matches, so
    // no key state may be derived from it.
    let mut tampered = KERI_CESR.to_vec();
    let pos = tampered
        .windows(5)
        .position(|w| w == b"\"kt\":")
        .expect("inception has a kt field");
    tampered[pos + 6] = b'9';

    assert!(resolve_from_artifacts(&did(), &tampered, Some(DID_JSON)).is_err());
}

#[test]
fn a_stream_for_a_different_aid_is_rejected() {
    let other = DidWebs::parse(
        "did:webs:did-webs-service%3a7676:ENotInThisStream00000000000000000000000000",
    )
    .expect("valid did");
    let err = resolve_from_artifacts(&other, KERI_CESR, None)
        .expect_err("a stream that does not contain the AID's KEL must not resolve");
    assert!(err.to_string().contains("no key events"), "{err}");
}

// -- served over HTTP, against a mock host -------------------------------

use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Serve the real artifacts and resolve them, so URL derivation and the fetch
/// path are exercised rather than assumed.
#[tokio::test]
async fn resolves_over_http() {
    let server = MockServer::start().await;
    let host = server.address().to_string().replace(':', "%3A");

    Mock::given(method("GET"))
        .and(path(format!("/{AID}/keri.cesr")))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(KERI_CESR))
        .mount(&server)
        .await;

    let parsed = did_from_host(&host);
    assert_eq!(
        parsed.artifact_url("keri.cesr"),
        format!("https://{}/{AID}/keri.cesr", server.address()),
        "artifact URL puts the AID before the file name",
    );

    let cesr = reqwest::get(format!("{}/{AID}/keri.cesr", server.uri()))
        .await
        .expect("fetch")
        .bytes()
        .await
        .expect("body");

    // No did.json here: the fixture's is bound to its own host (see the next
    // test), and the key event log alone fully determines the answer.
    let doc = resolve_from_artifacts(&parsed, &cesr, None).expect("served artifacts resolve");
    assert_eq!(doc.verification_method.len(), 1);
    assert!(
        doc.verification_method[0]
            .id
            .as_str()
            .ends_with(&format!("#{SIGNING_KEY}")),
    );
}

/// A published document names the identifier it belongs to, so the same
/// `did.json` served from a different host is refused. Without this, a
/// document could be lifted from one host and replayed at another.
#[test]
fn a_did_json_cannot_be_reused_at_another_host() {
    let elsewhere =
        DidWebs::parse(&format!("did:webs:someone-else.example:{AID}")).expect("valid did");

    let err = resolve_from_artifacts(&elsewhere, KERI_CESR, Some(DID_JSON))
        .expect_err("a document bound to another host must be refused");
    assert!(err.to_string().contains("which is neither"), "{err}");
}

fn did_from_host(host: &str) -> DidWebs {
    DidWebs::parse(&format!("did:webs:{host}:{AID}")).expect("valid did")
}
