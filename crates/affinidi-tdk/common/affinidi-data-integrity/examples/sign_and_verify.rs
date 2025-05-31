use affinidi_data_integrity::{
    DataIntegrityProof, GenericDocument, verification_proof::verify_data,
};
use affinidi_secrets_resolver::secrets::Secret;

fn main() {
    let input_doc_str = r#"{
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
    "witness": {
      "threshold": 2,
      "witnesses": [
        {
          "id": "did:key:z6MkroJ5yTPH9CDGT1YqXXUPsiS46b7xoDFaKAAaH32FoNRG"
        },
        {
          "id": "did:key:z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm"
        },
        {
          "id": "did:key:z6Mkp2m3BqokMHQ4f64HG1qxpZtjgfuT3NDZKVfsbdFnNsfH"
        }
      ]
    },
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
}"#;

    let unsigned_values: GenericDocument =
        serde_json::from_str(input_doc_str).expect("Couldn't serialize input string");

    let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
    let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";

    let secret = Secret::from_multibase(
        &format!("did:key:{}#{}", pub_key, pub_key),
        pub_key,
        pri_key,
    )
    .expect("Couldn't create Secret");

    let signed = DataIntegrityProof::sign_data_jcs(&unsigned_values, &secret.id, &secret)
        .expect("Couldn't sign Document");

    let result =
        verify_data(&serde_json::from_value(signed).expect("Couldn't convert genericDocument"))
            .expect("Couldn't validate doc");

    println!("Signed Document: {:#?}", result);
}
