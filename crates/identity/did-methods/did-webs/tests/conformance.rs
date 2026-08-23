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

// -- designated aliases --------------------------------------------------

use affinidi_did_webs::{Kels, designated_aliases};

const REGISTRY: &str = "EHfE7gojVcX5Ldu8zzBr9WZhVz2ZP7XoYDaVEtqcyDRP";
const ATTESTATION: &str = "EIEXitNCXQ_Y7HC6I7oiY7fPrRJyJzwvn_YIjvSHPzav";

#[test]
fn verifies_the_designated_aliases_chain() {
    let kels = Kels::parse(KERI_CESR).expect("stream parses");
    let found = designated_aliases(&kels, AID).expect("KEL verifies");

    assert!(found.rejected.is_none(), "{:?}", found.rejected);
    // The published attestation designates five aliases.
    assert_eq!(found.aliases.len(), 5, "got {:?}", found.aliases);
    assert!(
        found
            .aliases
            .contains(&format!("did:webs:did-webs-service%3a7676:{AID}")),
        "got {:?}",
        found.aliases,
    );
}

#[test]
fn resolved_document_carries_the_verified_aliases() {
    let doc = resolve_from_artifacts(&did(), KERI_CESR, None).expect("resolves");

    // The did:web twin holds without attestation; the rest are designated.
    assert!(
        doc.also_known_as.len() > 1,
        "expected designated aliases beyond the twin, got {:?}",
        doc.also_known_as,
    );
    assert!(
        doc.also_known_as
            .iter()
            .any(|a| a == &format!("did:webs:foo.com:{AID}")),
        "got {:?}",
        doc.also_known_as,
    );
}

/// Cut one message (and its attachments) out of the stream, by its own SAID.
///
/// Matching on the first `"d":"<said>"` anywhere in the stream is wrong: a
/// SAID appears in the seals that anchor it as well as in the message itself,
/// and the first hit for a registry id is the KEL event anchoring it. Removing
/// that instead breaks the key event log. So each message range is examined,
/// and only its *own* `d` — the first one inside that range, since `d` comes
/// third in a KERI event and second in an ACDC — is compared.
fn without_message(stream: &[u8], said: &str) -> Vec<u8> {
    let text = std::str::from_utf8(stream).expect("ascii stream");

    let mut starts: Vec<usize> = text.match_indices("{\"v\":\"").map(|(i, _)| i).collect();
    starts.push(text.len());

    for window in starts.windows(2) {
        let (start, end) = (window[0], window[1]);
        let range = &text[start..end];
        let Some(d_at) = range.find("\"d\":\"") else {
            continue;
        };
        let value_at = d_at + 5;
        if range[value_at..].starts_with(said) {
            let mut out = text.as_bytes()[..start].to_vec();
            out.extend_from_slice(&text.as_bytes()[end..]);
            return out;
        }
    }

    panic!("no message in the stream has SAID {said}");
}

/// Build a KERI event with the byte-accurate size in its version string.
///
/// The version string declares the message length and the parser slices the
/// stream by it, so an event with a stale size derails everything after it.
/// The size is measured from the serialized form rather than assumed.
fn keri_event(mut sad: serde_json::Value) -> Vec<u8> {
    let len = serde_json::to_vec(&sad).expect("serializes").len();
    sad["v"] = serde_json::json!(format!("KERI10JSON{len:06x}_"));
    serde_json::to_vec(&sad).expect("serializes")
}

#[test]
fn an_attestation_without_its_registry_designates_nothing() {
    // Remove the registry inception. The attestation is untouched and still
    // signed by the AID — but nothing establishes the registry it claims to
    // have been issued in, so its aliases must not be repeated.
    //
    // This cannot be tested by *tampering*: every KERI event is bound to its
    // own SAID, so altering an anchor breaks the event carrying it and the
    // whole key event log fails first. Removing a message is the only way to
    // isolate this one link in the chain.
    let stream = without_message(KERI_CESR, REGISTRY);

    let kels = Kels::parse(&stream).expect("still parses");
    let found = designated_aliases(&kels, AID).expect("KEL still verifies");
    assert!(
        found.aliases.is_empty(),
        "a registry with no inception must yield no aliases, got {:?}",
        found.aliases,
    );
    assert!(
        found
            .rejected
            .as_deref()
            .is_some_and(|r| r.contains("no inception event")),
        "{:?}",
        found.rejected,
    );
}

#[test]
fn an_attestation_without_its_issuance_designates_nothing() {
    // The registry is real and anchored, but nothing says this credential was
    // ever issued in it.
    let stream = without_message(KERI_CESR, "EBK4vxXrJS0V42rbuX4Sgx2pYXV_WRKuH5dkqGepKPQ4");

    let kels = Kels::parse(&stream).expect("still parses");
    let found = designated_aliases(&kels, AID).expect("KEL still verifies");
    assert!(found.aliases.is_empty(), "got {:?}", found.aliases);
    assert!(
        found
            .rejected
            .as_deref()
            .is_some_and(|r| r.contains("no issuance event")),
        "{:?}",
        found.rejected,
    );
}

#[test]
fn a_revoked_attestation_designates_nothing() {
    // A claimed revocation is enough to stop repeating the aliases.
    let mut stream = KERI_CESR.to_vec();
    stream.extend_from_slice(&keri_event(serde_json::json!({
        "v": "KERI10JSON000000_",
        "t": "rev",
        "d": "ERevocation000000000000000000000000000000000",
        "i": ATTESTATION,
        "s": "1",
        "ri": REGISTRY,
        "dt": "2024-01-01T00:00:00.000000+00:00",
    })));

    let kels = Kels::parse(&stream).expect("parses");
    let found = designated_aliases(&kels, AID).expect("KEL verifies");
    assert!(
        found.aliases.is_empty(),
        "a revoked attestation must designate nothing, got {:?}",
        found.aliases,
    );
    assert!(
        found
            .rejected
            .as_deref()
            .is_some_and(|r| r.contains("revoked")),
        "{:?}",
        found.rejected,
    );
}

#[test]
fn another_aid_cannot_claim_this_attestation() {
    // The attestation is issued by ENro7uf0…; asking for a different AID's
    // aliases must not return it. That AID has no KEL here, so this also
    // pins that a missing KEL is an error rather than an empty answer.
    let kels = Kels::parse(KERI_CESR).expect("parses");
    assert!(designated_aliases(&kels, REGISTRY).is_err());
}
