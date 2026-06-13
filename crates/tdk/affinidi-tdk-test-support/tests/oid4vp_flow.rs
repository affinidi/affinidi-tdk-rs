//! TI5b — OID4VP present/verify flows on `CredentialScenario`: both eIDAS
//! mandatory formats (`vc+sd-jwt` and `mso_mdoc`) carried through the OID4VP
//! authorization request/response envelope, plus the nonce-replay and
//! envelope-mismatch negatives. All synchronous, no network.

use std::collections::BTreeMap;

use affinidi_openid4vp::{PresentationDefinition, verifier::create_input_descriptor};
use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
use serde_json::json;

const CLIENT_ID: &str = "https://verifier.example";
const NONCE: &str = "oid4vp-nonce-1";
const VCT: &str = "https://example.com/IdentityCredential";
const DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";
const NS: &str = "eu.europa.ec.eudi.pid.1";

fn definition(id: &str) -> PresentationDefinition {
    PresentationDefinition {
        id: id.to_string(),
        name: None,
        purpose: Some("identity".to_string()),
        input_descriptors: vec![create_input_descriptor(
            "credential",
            "identity",
            vec![("given_name", None)],
        )],
        submission_requirements: None,
        format: None,
    }
}

fn sd_jwt_claims() -> serde_json::Value {
    json!({ "given_name": "Alice", "family_name": "Smith", "email": "alice@example.com" })
}

fn sd_frame() -> serde_json::Value {
    json!({ "_sd": ["given_name", "family_name", "email"] })
}

fn mdoc_request(namespace: &str, names: &[&str]) -> BTreeMap<String, Vec<String>> {
    let mut requested = BTreeMap::new();
    requested.insert(
        namespace.to_string(),
        names.iter().map(|s| s.to_string()).collect(),
    );
    requested
}

/// SD-JWT VC over OID4VP: verifier requests, holder presents (vp_token = SD-JWT
/// compact serialization), verifier validates the envelope and verifies the
/// credential.
#[test]
fn oid4vp_sd_jwt_round_trip() {
    let scenario = CredentialScenario::new();
    let request = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-sd-jwt"));

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &sd_jwt_claims(), &sd_frame())
        .expect("issue sd-jwt-vc");
    let response = scenario
        .oid4vp_present_sd_jwt(&request, &vc, &["given_name"])
        .expect("present over oid4vp");

    let result = scenario
        .oid4vp_verify_sd_jwt(&request, &response)
        .expect("verify over oid4vp");
    assert!(result.is_verified());
    assert_eq!(
        result.claims.get("given_name").and_then(|v| v.as_str()),
        Some("Alice")
    );
    // Withheld selectively-disclosable claims must not surface.
    assert!(result.claims.get("email").is_none());
}

/// Negative: a presentation bound to one nonce must be rejected when the
/// verifier checks it against a request carrying a different nonce (replay /
/// freshness binding), even though the envelope itself is well-formed.
#[test]
fn oid4vp_sd_jwt_nonce_mismatch_is_rejected() {
    let scenario = CredentialScenario::new();
    let request = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-sd-jwt"));

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &sd_jwt_claims(), &sd_frame())
        .expect("issue");
    let response = scenario
        .oid4vp_present_sd_jwt(&request, &vc, &["given_name"])
        .expect("present");

    // Same client_id + definition (envelope validates) but a different nonce →
    // the KB-JWT nonce check fails.
    let stale = scenario.oid4vp_request(CLIENT_ID, "different-nonce", definition("pd-sd-jwt"));
    assert!(
        scenario.oid4vp_verify_sd_jwt(&stale, &response).is_err(),
        "a nonce mismatch must be rejected"
    );
}

/// Negative: an envelope referencing the wrong presentation definition is
/// rejected by envelope validation before any credential check.
#[test]
fn oid4vp_definition_mismatch_is_rejected() {
    let scenario = CredentialScenario::new();
    let request = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-sd-jwt"));

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &sd_jwt_claims(), &sd_frame())
        .expect("issue");
    let response = scenario
        .oid4vp_present_sd_jwt(&request, &vc, &["given_name"])
        .expect("present");

    let other = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-other"));
    assert!(
        scenario.oid4vp_verify_sd_jwt(&other, &response).is_err(),
        "a definition_id mismatch must be rejected by envelope validation"
    );
}

/// mdoc over OID4VP: verifier requests, holder presents (vp_token =
/// base64url(CBOR(DeviceResponse))), verifier validates the envelope and
/// verifies issuer auth + digests.
#[test]
fn oid4vp_mdoc_round_trip() {
    let scenario = CredentialScenario::new();
    let request = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-mdoc"));

    let mdoc = scenario
        .issue_mdoc(
            DOC_TYPE,
            NS,
            &json!({ "given_name": "Erika", "age_over_18": true, "nationality": "DE" }),
        )
        .expect("issue mdoc");
    let response = scenario
        .oid4vp_present_mdoc(
            &request,
            &mdoc,
            &mdoc_request(NS, &["given_name", "age_over_18"]),
        )
        .expect("present mdoc over oid4vp");

    let mso = scenario
        .oid4vp_verify_mdoc(&request, &response)
        .expect("verify mdoc over oid4vp");
    assert_eq!(mso.doc_type, DOC_TYPE);
}

/// Negative: a tampered `mso_mdoc` vp_token fails decoding/verification while
/// the surrounding envelope still validates.
#[test]
fn oid4vp_mdoc_tampered_token_is_rejected() {
    let scenario = CredentialScenario::new();
    let request = scenario.oid4vp_request(CLIENT_ID, NONCE, definition("pd-mdoc"));

    let mdoc = scenario
        .issue_mdoc(DOC_TYPE, NS, &json!({ "given_name": "Erika" }))
        .expect("issue");
    let mut response = scenario
        .oid4vp_present_mdoc(&request, &mdoc, &mdoc_request(NS, &["given_name"]))
        .expect("present");

    // Corrupt the vp_token (not valid base64url) — the envelope is untouched.
    response.vp_token = serde_json::Value::String("!!!not-base64!!!".to_string());
    assert!(
        scenario.oid4vp_verify_mdoc(&request, &response).is_err(),
        "a tampered vp_token must be rejected"
    );
}
