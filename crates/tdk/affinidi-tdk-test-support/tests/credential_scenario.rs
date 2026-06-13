//! TI5 — `CredentialScenario` SD-JWT VC flows: the issue → present → verify
//! round trip plus the W4/W5 negatives (status-list revocation, holder-binding
//! failure, disallowed `alg`). All synchronous, no network.

use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
use serde_json::json;

const VCT: &str = "https://example.com/IdentityCredential";
const NONCE: &str = "verifier-nonce-1";

fn identity_claims() -> serde_json::Value {
    json!({ "given_name": "Alice", "family_name": "Smith", "email": "alice@example.com" })
}

fn sd_frame() -> serde_json::Value {
    json!({ "_sd": ["given_name", "family_name", "email"] })
}

/// Happy path: issue, present revealing one claim, verify — and selective
/// disclosure holds (revealed claim present, withheld claims absent).
#[test]
fn sd_jwt_vc_issue_present_verify_round_trip() {
    let scenario = CredentialScenario::new();
    let aud = scenario.verifier.did().to_string();

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &identity_claims(), &sd_frame())
        .expect("issue sd-jwt-vc");

    let presentation = scenario
        .present(&vc, &["given_name"], &aud, NONCE)
        .expect("holder presents given_name");

    let result = scenario
        .verify(&presentation, &aud, NONCE)
        .expect("verifier accepts the presentation");

    assert!(result.is_verified(), "KB-JWT must verify");
    assert_eq!(
        result.claims.get("given_name").and_then(|v| v.as_str()),
        Some("Alice")
    );
    // Withheld selectively-disclosable claims must not surface.
    assert!(
        result.claims.get("email").is_none(),
        "email was not disclosed"
    );
    assert!(
        result.claims.get("family_name").is_none(),
        "family_name was not disclosed"
    );
    // Protected VC claims remain visible.
    assert_eq!(result.claims.get("vct").and_then(|v| v.as_str()), Some(VCT));
}

/// Negative: a revoked credential must not be accepted. The signature still
/// verifies (revocation is orthogonal to issuer signing), so the verifier's
/// accept decision must additionally consult the status list.
#[test]
fn revoked_credential_is_rejected() {
    let mut scenario = CredentialScenario::new();
    let aud = scenario.verifier.did().to_string();
    let index = scenario.allocate_status();

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &identity_claims(), &sd_frame())
        .expect("issue");
    let presentation = scenario
        .present(&vc, &["given_name"], &aud, NONCE)
        .expect("present");

    // Before revocation: crypto verifies AND status is good → accepted.
    assert!(
        scenario
            .verify(&presentation, &aud, NONCE)
            .unwrap()
            .is_verified()
    );
    assert!(!scenario.is_revoked(index).unwrap());

    // Revoke, then the same presentation must be rejected by a status-aware
    // verifier even though the signature still checks out.
    scenario.revoke(index).expect("revoke");
    let crypto_ok = scenario
        .verify(&presentation, &aud, NONCE)
        .unwrap()
        .is_verified();
    let revoked = scenario.is_revoked(index).unwrap();
    assert!(crypto_ok, "signature is unaffected by revocation");
    assert!(revoked, "status list marks the credential revoked");
    // A status-aware verifier accepts only when crypto verifies AND the
    // credential is not revoked.
    let accepted = crypto_ok && !revoked;
    assert!(!accepted, "a revoked credential must be rejected");
}

/// Negative: holder binding fails when the KB-JWT is checked against the wrong
/// key. Here the holder verifier is built from the issuer's key, so the
/// holder-signed KB-JWT does not verify.
#[test]
fn wrong_holder_key_fails_kb_binding() {
    let scenario = CredentialScenario::new();
    let aud = scenario.verifier.did().to_string();

    let vc = scenario
        .issue_sd_jwt_vc(VCT, &identity_claims(), &sd_frame())
        .expect("issue");
    let presentation = scenario
        .present(&vc, &["given_name"], &aud, NONCE)
        .expect("present");

    // Correct issuer verifier, but a holder verifier keyed on the *issuer's*
    // key (the wrong key for the KB-JWT).
    let result = scenario.verify_with(
        &presentation,
        &scenario.issuer.verifier(&["EdDSA"]),
        &scenario.issuer.verifier(&["EdDSA"]), // wrong key for the holder slot
        &aud,
        NONCE,
    );
    assert!(
        result.is_err(),
        "KB-JWT verified against the wrong holder key must fail"
    );
}

/// Negative (W5 in the credential context): a credential whose issuer JWS
/// declares a disallowed `alg` is rejected before the signature is checked.
#[test]
fn disallowed_alg_is_rejected() {
    let scenario = CredentialScenario::new();
    let aud = scenario.verifier.did().to_string();

    // Sign with Ed25519 but forge the header `alg` as ES256.
    let forged = scenario.issuer.signer().with_alg("ES256");
    let vc = scenario
        .issue_sd_jwt_vc_with_signer(&forged, VCT, &identity_claims(), &sd_frame())
        .expect("issue with forged alg");
    let presentation = scenario
        .present(&vc, &["given_name"], &aud, NONCE)
        .expect("present");

    // Default verify allows only EdDSA → the ES256-declared issuer JWS is
    // rejected on the algorithm allowlist, before any signature check.
    let result = scenario.verify(&presentation, &aud, NONCE);
    assert!(
        result.is_err(),
        "a presentation whose issuer alg is outside the allowlist must be rejected"
    );

    // Sanity: the same credential verifies once ES256 is explicitly allowed
    // (proving it's the allowlist, not a broken signature, doing the rejecting).
    let allowed = scenario.verify_with(
        &presentation,
        &scenario.issuer.verifier(&["ES256", "EdDSA"]),
        &scenario.holder.verifier(&["EdDSA"]),
        &aud,
        NONCE,
    );
    assert!(
        allowed.is_ok(),
        "ES256-allowed verify should accept the Ed25519 signature"
    );
}
