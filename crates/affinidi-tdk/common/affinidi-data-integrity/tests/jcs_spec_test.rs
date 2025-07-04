use affinidi_data_integrity::{
    DataIntegrityProof, SignedDocument, SigningDocument, verification_proof::verify_data,
};
use affinidi_secrets_resolver::secrets::Secret;
use tracing_subscriber::filter;

#[test]
fn eddsa_jcs_2022_reference() {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let input_doc_str = r#"{
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
}"#;

    let mut unsigned_values: SigningDocument =
        serde_json::from_str(input_doc_str).expect("Couldn't serialize input string");

    let pub_key = "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2";
    let pri_key = "z3u2en7t5LR2WtQH5PfFqMqwVHBeXouLzo6haApm8XHqvjxq";

    let secret = Secret::from_multibase(&format!("did:key:{pub_key}#{pub_key}"), pub_key, pri_key)
        .expect("Couldn't create Secret");

    DataIntegrityProof::sign_jcs_data(
        &mut unsigned_values,
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .expect("Couldn't sign Document");

    let signed = SignedDocument {
        extra: unsigned_values.extra,
        proof: unsigned_values.proof.clone(),
    };
    let validated = verify_data(&signed).expect("Couldn't validate doc");

    assert!(validated.verified);

    let Some(proof) = &unsigned_values.proof else {
        panic!("Proof should not be None");
    };

    let Some(proof_value) = &proof.proof_value else {
        panic!("Proof value should not be None");
    };

    assert_eq!(
        proof_value.as_str(),
        "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
    );
}
