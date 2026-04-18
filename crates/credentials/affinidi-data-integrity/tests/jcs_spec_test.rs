use affinidi_data_integrity::{DataIntegrityProof, SignOptions, VerifyOptions};
use affinidi_secrets_resolver::secrets::Secret;
use chrono::DateTime;
use serde_json::json;
use tracing_subscriber::filter;

#[tokio::test]
async fn eddsa_jcs_2022_reference() {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    let _ = tracing::subscriber::set_global_default(subscriber);

    let input_doc = json!( {
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
    }}
    );

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

    let created = "2023-02-24T23:36:38Z".parse::<DateTime<_>>().unwrap();
    let proof = DataIntegrityProof::sign(
        &input_doc,
        &secret,
        SignOptions::new()
            .with_context(context.clone())
            .with_created(created),
    )
    .await
    .expect("Couldn't sign Document");

    proof
        .verify_with_public_key(
            &input_doc,
            secret.get_public_bytes(),
            VerifyOptions::new().with_expected_context(context),
        )
        .expect("Couldn't validate doc");

    let Some(proof_value) = &proof.proof_value else {
        panic!("Proof value should not be None");
    };

    assert_eq!(
        proof_value.as_str(),
        "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
    );
}
