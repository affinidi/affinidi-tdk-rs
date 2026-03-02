use affinidi_data_integrity::{
    DataIntegrityProof, verification_proof::verify_data_with_public_key,
};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;
use tracing_subscriber::filter;

/// W3C vc-di-eddsa B.1 test vectors for eddsa-rdfc-2022
/// Uses the same Alumni Credential and key pair as the JCS reference test.
#[test]
fn eddsa_rdfc_2022_reference() {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let input_doc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
        }
    });

    let context: Vec<String> = input_doc
        .get("@context")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();

    let pub_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let pri_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
        .expect("Couldn't create Secret");

    let proof = DataIntegrityProof::sign_rdfc_data(
        &input_doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .expect("Couldn't sign Document");

    // Verify the proof value matches the W3C spec expected output
    let Some(proof_value) = &proof.proof_value else {
        panic!("Proof value should not be None");
    };

    assert_eq!(
        proof_value.as_str(),
        "z2YwC8z3ap7yx1nZYCg4L3j3ApHsF8kgPdSb5xoS1VR7vPG3F561B52hYnQF9iseabecm3ijx4K1FBTQsCZahKZme",
        "Proof value does not match W3C vc-di-eddsa B.1 expected output"
    );

    // Verify round-trip through verify_data_with_public_key
    let validated = verify_data_with_public_key(
        &input_doc,
        Some(context),
        &proof,
        secret.get_public_bytes(),
    )
    .expect("Couldn't validate doc");

    assert!(validated.verified);
}

/// Verify that a JCS-signed document cannot be verified through the RDFC path
#[test]
fn jcs_proof_cannot_verify_as_rdfc() {
    let input_doc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
        }
    });

    let context: Vec<String> = input_doc
        .get("@context")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();

    let pub_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let pri_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
        .expect("Couldn't create Secret");

    // Sign with JCS
    let mut jcs_proof = DataIntegrityProof::sign_jcs_data(
        &input_doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .expect("Couldn't sign Document with JCS");

    // Tamper with the cryptosuite to pretend it's RDFC
    jcs_proof.cryptosuite = affinidi_data_integrity::crypto_suites::CryptoSuite::EddsaRdfc2022;

    // Verification should fail
    let result = verify_data_with_public_key(
        &input_doc,
        Some(context),
        &jcs_proof,
        secret.get_public_bytes(),
    );

    assert!(
        result.is_err(),
        "JCS-signed document should not verify through RDFC path"
    );
}

/// Verify that an RDFC-signed document cannot be verified through the JCS path
#[test]
fn rdfc_proof_cannot_verify_as_jcs() {
    let input_doc = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://www.w3.org/ns/credentials/examples/v2"
        ],
        "id": "urn:uuid:58172aac-d8ba-11ed-83dd-0b3aef56cc33",
        "type": ["VerifiableCredential", "AlumniCredential"],
        "name": "Alumni Credential",
        "description": "A minimum viable example of an Alumni Credential.",
        "issuer": "https://vc.example/issuers/5678",
        "validFrom": "2023-01-01T00:00:00Z",
        "credentialSubject": {
            "id": "did:example:abcdefgh",
            "alumniOf": "The School of Examples"
        }
    });

    let context: Vec<String> = input_doc
        .get("@context")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e.as_str().unwrap().to_string())
        .collect();

    let pub_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let pri_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
        .expect("Couldn't create Secret");

    // Sign with RDFC
    let mut rdfc_proof = DataIntegrityProof::sign_rdfc_data(
        &input_doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .expect("Couldn't sign Document with RDFC");

    // Tamper with the cryptosuite to pretend it's JCS
    rdfc_proof.cryptosuite = affinidi_data_integrity::crypto_suites::CryptoSuite::EddsaJcs2022;

    // Verification should fail
    let result = verify_data_with_public_key(
        &input_doc,
        Some(context),
        &rdfc_proof,
        secret.get_public_bytes(),
    );

    assert!(
        result.is_err(),
        "RDFC-signed document should not verify through JCS path"
    );
}
