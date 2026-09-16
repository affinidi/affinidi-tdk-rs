//! Verification of proofs produced by *other* Data Integrity implementations.
//!
//! The rest of this crate's tests sign with this crate and verify with this
//! crate, which cannot catch a disagreement about what a proof *is* — a field
//! this crate never writes is a field its own round trips never exercise. That
//! is exactly how `DataIntegrityProof` came to drop `nonce`: this crate's signer
//! never sets one, so every self-produced proof round-tripped cleanly, while a
//! producer that does set one had every proof rejected as `signature invalid`.
//!
//! Fixtures live under `tests/fixtures/interop/` — see the README there for
//! where each came from and why none of them is regenerated.

use affinidi_data_integrity::{DataIntegrityProof, DidKeyResolver, VerifyOptions};
use serde_json::Value;

const SSI_DART_NONCE: &str =
    include_str!("fixtures/interop/affinidi-ssi-dart-eddsa-jcs-2022-nonce.json");

/// Split a signed document into the document the proof covers and the proof.
fn split(fixture: &str) -> (Value, Value) {
    let mut doc: Value = serde_json::from_str(fixture).expect("fixture is JSON");
    let proof = doc
        .as_object_mut()
        .expect("fixture is an object")
        .remove("proof")
        .expect("fixture carries a proof");
    (doc, proof)
}

async fn verify(doc: &Value, proof: Value) -> Result<(), String> {
    let proof: DataIntegrityProof = serde_json::from_value(proof).map_err(|e| e.to_string())?;
    proof
        .verify(doc, &DidKeyResolver, VerifyOptions::default())
        .await
        .map_err(|e| e.to_string())
}

/// The case that exposed the bug. `affinidi-ssi-dart` sets `nonce` on every
/// proof, and every cryptosuite hashes the proof configuration — so a verifier
/// that drops `nonce` hashes bytes the signer never signed.
#[tokio::test]
async fn verifies_an_affinidi_ssi_dart_proof_that_carries_a_nonce() {
    let (doc, proof) = split(SSI_DART_NONCE);
    assert!(
        proof.get("nonce").and_then(Value::as_str).is_some(),
        "fixture must carry a nonce, or this test proves nothing"
    );

    verify(&doc, proof)
        .await
        .expect("a valid foreign proof carrying a nonce must verify");
}

/// Accepting the field is not enough — it must be *bound*. If `nonce` were
/// deserialized and then ignored when hashing, a proof would verify with any
/// nonce at all, which is the property this asserts cannot happen.
#[tokio::test]
async fn nonce_is_covered_by_the_signature() {
    let (doc, mut proof) = split(SSI_DART_NONCE);
    proof["nonce"] = Value::String("0000000000000000000000000000000".to_string());

    assert!(
        verify(&doc, proof).await.is_err(),
        "a proof whose nonce was altered after signing must not verify"
    );
}

/// The converse of the above: stripping the nonce changes the signed
/// configuration too, so it must not be silently accepted.
#[tokio::test]
async fn a_stripped_nonce_does_not_verify() {
    let (doc, mut proof) = split(SSI_DART_NONCE);
    proof.as_object_mut().unwrap().remove("nonce");

    assert!(
        verify(&doc, proof).await.is_err(),
        "a proof whose nonce was removed after signing must not verify"
    );
}

/// This crate's own signer does not set `nonce`, and adding the field must not
/// make it start emitting one — `skip_serializing_if` is what keeps existing
/// signed output byte-identical, which `tests/fixtures.rs` also pins.
#[test]
fn an_absent_nonce_is_not_serialized() {
    let (_, mut proof) = split(SSI_DART_NONCE);
    proof.as_object_mut().unwrap().remove("nonce");

    let parsed: DataIntegrityProof = serde_json::from_value(proof).unwrap();
    assert!(parsed.nonce.is_none());
    let reserialized = serde_json::to_value(&parsed).unwrap();
    assert!(
        reserialized.get("nonce").is_none(),
        "an absent nonce must not appear as `\"nonce\": null`"
    );
}
