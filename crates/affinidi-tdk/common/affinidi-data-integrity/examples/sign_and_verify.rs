use affinidi_data_integrity::{
    DataIntegrityProof, verification_proof::verify_data_with_public_key,
};
use affinidi_secrets_resolver::secrets::Secret;
use serde_json::json;
use tracing_subscriber::filter;

fn main() {
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = tracing_subscriber::fmt()
        // Use a more compact, abbreviated log format
        .with_env_filter(filter::EnvFilter::from_default_env())
        .finish();
    // use that subscriber to process traces emitted after this point
    tracing::subscriber::set_global_default(subscriber).expect("Logging failed, exiting...");

    let input_doc = json!({
    "version_id": "1-zQmW7ssogG8fwWBZTdH47S4vntYJzVB4vbXR1pYsAhriNh4",
    "version_time": "2025-05-31T02:11:02Z",
    "parameters": {
      "method": "did:webvh:1.0",
      "scid": "zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7",
      "update_keys": [
        "z6MkkkpnVE5PnEyJPLJ4GFdas8Grykt2L3E2gqCbK7ktui8v"
      ],
      "portable": true,
      "next_key_hashes": [
        "zQmcTKbHERk1Q5QsUBnTbnhJhdwnSREyoS3duyLuPBWDUPA"
      ],
      "deactivated": false
    },
    "state": {
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://www.w3.org/ns/cid/v1"
      ],
      "assertionMethod": [
        "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
      ],
      "authentication": [
        "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
      ],
      "capabilityDelegation": [],
      "capabilityInvocation": [],
      "id": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000",
      "keyAgreement": [
        "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
      ],
      "service": [],
      "verificationMethod": [
        {
          "controller": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000",
          "id": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0",
          "publicKeyMultibase": "z6Mkn6Rwmuzpc8wvErSX4WbDW4Cu3XVtbdRV9fGdb2hea4Fs",
          "type": "Multikey"
        }
      ]
    }
      }
      );

    let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
    let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";

    let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
        .expect("Couldn't create Secret");

    let proof = DataIntegrityProof::sign_jcs_data(&input_doc, None, &secret, None)
        .expect("Couldn't sign Document");

    let _ = verify_data_with_public_key(&input_doc, None, &proof, secret.get_public_bytes())
        .expect("Couldn't validate doc");

    println!(
        "Signed Document proof: {}",
        serde_json::to_string_pretty(&proof).unwrap()
    );
}
