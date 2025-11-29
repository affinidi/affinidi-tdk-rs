use affinidi_data_integrity::{DataIntegrityProof, verification_proof::verify_data};
use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};
use affinidi_secrets_resolver::secrets::Secret;
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
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

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

    let proof = DataIntegrityProof::sign_jcs_data(
        &input_doc,
        Some(context.clone()),
        &secret,
        Some("2023-02-24T23:36:38Z".to_string()),
    )
    .expect("Couldn't sign Document");

    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .unwrap();
    let validated = verify_data(&resolver, &input_doc, Some(context), &proof)
        .await
        .expect("Couldn't validate doc");

    assert!(validated.verified);

    let Some(proof_value) = &proof.proof_value else {
        panic!("Proof value should not be None");
    };

    assert_eq!(
        proof_value.as_str(),
        "z2HnFSSPPBzR36zdDgK8PbEHeXbR56YF24jwMpt3R1eHXQzJDMWS93FCzpvJpwTWd3GAVFuUfjoJdcnTMuVor51aX",
    );
}
