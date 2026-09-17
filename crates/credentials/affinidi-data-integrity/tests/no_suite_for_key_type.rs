//! A key type with no Data Integrity cryptosuite is refused by name, not by
//! implicating Ed25519.

use affinidi_data_integrity::crypto_suites::CryptoSuite;
use affinidi_data_integrity::{DataIntegrityError, DataIntegrityProof, SignOptions};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;

fn doc() -> serde_json::Value {
    json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "id": "urn:uuid:no-suite-probe",
    })
}

/// **The regression.** An ML-DSA-65 key has no Data Integrity suite, and the
/// refusal must say so.
///
/// It used to report `KeyTypeMismatch { expected: Ed25519, actual: MlDsa65,
/// suite: EddsaJcs2022 }`. The caller never chose an Ed25519 suite —
/// `Signer::cryptosuite()`'s default is
/// `default_for_key_type(..).unwrap_or(EddsaJcs2022)`, so the library invented
/// one and then blamed the caller for it, naming an algorithm that appears
/// nowhere in their configuration.
///
/// Reachable in practice: a VTA can mint an ML-DSA-65 key, so an operator can
/// hold one and be told their problem is Ed25519.
#[tokio::test]
async fn an_ml_dsa_65_key_is_refused_by_naming_the_missing_suite() {
    let secret = Secret::generate_ml_dsa_65(None, None);

    let err = DataIntegrityProof::sign(&doc(), &secret, SignOptions::default())
        .await
        .expect_err("ML-DSA-65 has no Data Integrity cryptosuite");

    let DataIntegrityError::UnsupportedCryptoSuite { name } = &err else {
        panic!(
            "the refusal must name the missing suite, not implicate a key type the caller \
             never chose: {err:?}"
        );
    };
    assert!(
        name.contains("MlDsa65"),
        "the message must name the key that has no suite: {name}"
    );
    assert!(
        !name.contains("Ed25519"),
        "Ed25519 is the library's invented default and has nothing to do with the caller's \
         problem; naming it is what sent people looking in the wrong place: {name}"
    );
}

/// ML-DSA-44 *does* have a suite, so it signs — the check above must not have
/// been implemented by refusing post-quantum keys generally.
#[tokio::test]
async fn ml_dsa_44_still_signs() {
    let secret = Secret::generate_ml_dsa_44(None, None);
    DataIntegrityProof::sign(&doc(), &secret, SignOptions::default())
        .await
        .expect("ML-DSA-44 is the parameter set W3C defines suites for");
}

/// A caller who *does* name a suite and hands it the wrong key still gets
/// `KeyTypeMismatch` — that diagnosis is correct for that case, and the fix
/// must not have swallowed it.
#[tokio::test]
async fn an_explicitly_chosen_wrong_suite_is_still_a_key_type_mismatch() {
    let secret = Secret::generate_ml_dsa_44(None, None);
    let options = SignOptions::new().with_cryptosuite(CryptoSuite::EddsaJcs2022);

    let err = DataIntegrityProof::sign(&doc(), &secret, options)
        .await
        .expect_err("an Ed25519 suite cannot take an ML-DSA key");

    assert!(
        matches!(err, DataIntegrityError::KeyTypeMismatch { .. }),
        "the caller named this suite, so the mismatch is theirs and the old diagnosis is the \
         right one: {err:?}"
    );
}
