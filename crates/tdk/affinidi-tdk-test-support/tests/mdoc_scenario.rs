//! TI5b — `CredentialScenario` mdoc COSE flows: the issue → present → verify
//! round trip (`sign_mso` / `verify_issuer_auth`), selective disclosure, holder
//! binding via device auth, and the wrong-key / disallowed-`alg` negatives. All
//! synchronous, no network.

use std::collections::BTreeMap;

use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
use coset::iana::Algorithm;
use serde_json::json;

const DOC_TYPE: &str = "eu.europa.ec.eudi.pid.1";
const NS: &str = "eu.europa.ec.eudi.pid.1";

fn pid_claims() -> serde_json::Value {
    json!({
        "family_name": "Mueller",
        "given_name": "Erika",
        "birth_date": "1964-08-12",
        "age_over_18": true,
        "nationality": "DE",
    })
}

fn request(namespace: &str, names: &[&str]) -> BTreeMap<String, Vec<String>> {
    let mut requested = BTreeMap::new();
    requested.insert(
        namespace.to_string(),
        names.iter().map(|s| s.to_string()).collect(),
    );
    requested
}

/// Happy path: issue, present a subset, verify issuer auth + digests, and
/// selective disclosure holds (only requested attributes are present).
#[test]
fn mdoc_issue_present_verify_round_trip() {
    let scenario = CredentialScenario::new();

    let mdoc = scenario
        .issue_mdoc(DOC_TYPE, NS, &pid_claims())
        .expect("issue mdoc");

    let response = scenario
        .present_mdoc(&mdoc, &request(NS, &["age_over_18", "nationality"]))
        .expect("present subset");

    let mso = scenario.verify_mdoc(&response).expect("verify mdoc");
    assert_eq!(mso.doc_type, DOC_TYPE);

    // Only the requested attributes are disclosed.
    let disclosed = response.disclosed_names(NS);
    assert_eq!(disclosed.len(), 2);
    assert!(disclosed.contains(&"age_over_18"));
    assert!(disclosed.contains(&"nationality"));
    assert!(!disclosed.contains(&"family_name"));
}

/// Holder binding: a device-signed presentation verifies against the holder
/// key, and fails against any other party's key.
#[test]
fn mdoc_holder_binding_succeeds_and_wrong_key_fails() {
    let scenario = CredentialScenario::new();
    let transcript = scenario.session_transcript().expect("transcript");

    let mdoc = scenario
        .issue_mdoc(DOC_TYPE, NS, &pid_claims())
        .expect("issue");
    let response = scenario
        .present_mdoc_with_binding(&mdoc, &request(NS, &["given_name"]), &transcript)
        .expect("present with binding");

    // Issuer auth still verifies, and the device signature checks out.
    scenario.verify_mdoc(&response).expect("issuer auth");
    assert!(
        scenario
            .verify_mdoc_binding(&response, &transcript)
            .expect("device auth"),
        "device signature must verify against the holder key"
    );

    // The same signature must NOT verify against the issuer's key.
    let wrong = response.verify_device_auth(&transcript, &scenario.issuer.cose_verifier());
    assert!(
        wrong.is_err() || !wrong.unwrap(),
        "device auth must fail against the wrong key"
    );
}

/// Negative: an mdoc signed by the issuer must not verify against another
/// party's key (the wrong issuer-auth key).
#[test]
fn mdoc_wrong_issuer_key_fails() {
    let scenario = CredentialScenario::new();
    let mdoc = scenario
        .issue_mdoc(DOC_TYPE, NS, &pid_claims())
        .expect("issue");
    let response = scenario
        .present_mdoc(&mdoc, &request(NS, &["given_name"]))
        .expect("present");

    // Verify issuerAuth against the holder's key instead of the issuer's.
    let result = response.verify_issuer_auth(&scenario.holder.cose_verifier());
    assert!(
        result.is_err(),
        "issuerAuth verified against the wrong key must fail"
    );
}

/// Negative (W5 in the mdoc context): an `issuerAuth` whose protected header
/// declares a disallowed `alg` is rejected before the signature is checked.
#[test]
fn mdoc_disallowed_alg_is_rejected() {
    let scenario = CredentialScenario::new();

    // Sign with Ed25519 but forge the protected-header `alg` as ES256.
    let forged = scenario.issuer.cose_signer_with_alg(Algorithm::ES256);
    let mdoc = scenario
        .issue_mdoc_with_signer(&forged, DOC_TYPE, NS, &pid_claims())
        .expect("issue with forged alg");
    let response = scenario
        .present_mdoc(&mdoc, &request(NS, &["given_name"]))
        .expect("present");

    // Default verify enforces EdDSA → the ES256-declared issuerAuth is rejected
    // on the algorithm check, before any signature verification.
    assert!(
        scenario.verify_mdoc(&response).is_err(),
        "an issuerAuth alg outside the allowlist must be rejected"
    );

    // Sanity: the same credential verifies once ES256 is the expected alg,
    // proving it's the allowlist — not a broken signature — doing the rejecting.
    let allowed = scenario.verify_mdoc_with_alg(&response, Algorithm::ES256);
    assert!(
        allowed.is_ok(),
        "ES256-expected verify should accept the Ed25519 signature"
    );
}
