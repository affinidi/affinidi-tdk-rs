use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use ssi::security::MultibaseBuf;
use tracing::debug;

use crate::{
    DataIntegrityError, DataIntegrityProof, SignedDocument, crypto_suites::CryptoSuite,
    hashing_eddsa_jcs,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationProof {
    /// true or false
    pub verified: bool,

    /// the verified document or None
    pub verified_document: Option<Value>,
}

/// Verify a signed JSON Schema document.
/// Must contain the field `proof`
pub fn verify_data(signed_doc: &SignedDocument) -> Result<VerificationProof, DataIntegrityError> {
    let mut verification_proof_result = VerificationProof {
        verified: false,
        verified_document: None,
    };

    // Strip proof from the signed document
    let mut proof_options: DataIntegrityProof = if let Some(proof) = &signed_doc.proof {
        proof.clone()
    } else {
        return Err(DataIntegrityError::InputDataError(
            "Signed document must contain a 'proof' field".to_string(),
        ));
    };

    // Strip Proof Value from the proof
    let proof_value = if let Some(proof_value) = proof_options.proof_value {
        MultibaseBuf::new(proof_value).decode().map_err(|e| {
            DataIntegrityError::InputDataError(format!("Invalid proof value: {}", e))
        })?
    } else {
        return Err(DataIntegrityError::InputDataError(
            "proofValue is missing in the proof".to_string(),
        ));
    };
    proof_options.proof_value = None;

    // Check @context if it exists
    // Must match between proof and Document
    let doc_context: Option<Vec<String>> = signed_doc
        .extra
        .get("@context")
        .map(|context| serde_json::from_value(context.to_owned()).unwrap());
    if doc_context != proof_options.context {
        return Err(DataIntegrityError::InputDataError(
            "Document context does not match proof context".to_string(),
        ));
    }

    // Run transformation
    if proof_options.type_ != "DataIntegrityProof" {
        return Err(DataIntegrityError::InputDataError(
            "Invalid proof type, expected 'DataIntegrityProof'".to_string(),
        ));
    }
    if proof_options.cryptosuite != CryptoSuite::EddsaJcs2022 {
        return Err(DataIntegrityError::InputDataError(
            "Unsupported cryptosuite, expected 'EddsaJcs2022'".to_string(),
        ));
    }

    let validation_doc = serde_json::to_value(&signed_doc.extra).map_err(|e| {
        DataIntegrityError::InputDataError(format!("Failed to serialize document: {}", e))
    })?;
    verification_proof_result.verified_document = Some(validation_doc.clone());

    debug!("Document: {:#?}", validation_doc);

    let jcs_doc = to_string(&validation_doc).map_err(|e| {
        DataIntegrityError::InputDataError(format!("Failed to canonicalize document: {}", e))
    })?;
    debug!("Document: {}", jcs_doc);

    // Run proof Configuration
    // Check Dates
    if let Some(created) = &proof_options.created {
        let now = Utc::now();
        let created = created.parse::<DateTime<Utc>>().map_err(|e| {
            DataIntegrityError::InputDataError(format!("Invalid created date: {}", e))
        })?;
        if created > now {
            return Err(DataIntegrityError::InputDataError(
                "Created date is in the future".to_string(),
            ));
        }
    }

    let proof_config = serde_json::to_value(&proof_options).map_err(|e| {
        DataIntegrityError::InputDataError(format!("Failed to serialize proof options: {}", e))
    })?;
    let jcs_proof_config = to_string(&proof_config).map_err(|e| {
        DataIntegrityError::InputDataError(format!("Failed to canonicalize proof config: {}", e))
    })?;
    debug!("proof options: {}", jcs_proof_config);

    // Hash the fields and join
    let hash_data = hashing_eddsa_jcs(&jcs_doc, &jcs_proof_config);

    // Create public key bytes from Verification Material
    if !proof_options.verification_method.starts_with("did:key:") {
        return Err(DataIntegrityError::InputDataError(
            "Verification method must start with 'did:key:'".to_string(),
        ));
    }
    let Some((_, public_key)) = proof_options.verification_method.split_once('#') else {
        return Err(DataIntegrityError::InputDataError(
            "Invalid verification method format".to_string(),
        ));
    };
    let secret = Secret::decode_multikey(public_key)
        .map_err(|e| DataIntegrityError::InputDataError(format!("Invalid public key: {}", e)))?;

    // Verify the signature
    let crypto = CryptoSuite::EddsaJcs2022;
    crypto
        .verify(
            secret.as_slice(),
            hash_data.as_slice(),
            proof_value.1.as_slice(),
        )
        .map_err(|e| {
            DataIntegrityError::VerificationError(format!("Signature verification failed: {}", e))
        })?;

    verification_proof_result.verified = true;
    Ok(verification_proof_result)
}

#[cfg(test)]
mod tests {
    use super::verify_data;
    use crate::{DataIntegrityError, SignedDocument, crypto_suites::CryptoSuite};
    use std::collections::HashMap;

    #[test]
    fn missing_proof() {
        let missing_proof = SignedDocument {
            extra: HashMap::new(),
            proof: None,
        };

        let result = verify_data(&missing_proof);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Signed document must contain a 'proof' field".to_string(),
            ))
        );
    }

    #[test]
    fn missing_proof_proof_value() {
        let missing_proof_value = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: None,
                context: None,
            }),
        };

        let result = verify_data(&missing_proof_value);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "proofValue is missing in the proof".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_proof_proof_value() {
        let invalid_proof_value = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("aaaaaaaaaa".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_proof_value);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid proof value: Unknown base code: a".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_context() {
        let mut invalid_context = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let signed_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/2".to_string(),
        ];
        invalid_context.extra.insert(
            "@context".to_string(),
            serde_json::to_value(&signed_context).unwrap(),
        );

        let result = verify_data(&invalid_context);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Document context does not match proof context".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_context_2() {
        let signed_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/2".to_string(),
        ];
        let invalid_context = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: Some(signed_context),
            }),
        };

        let result = verify_data(&invalid_context);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Document context does not match proof context".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_context_3() {
        let signed_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/2".to_string(),
        ];
        let mut invalid_context = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: Some(signed_context),
            }),
        };

        let doc_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/3".to_string(),
        ];
        invalid_context.extra.insert(
            "@context".to_string(),
            serde_json::to_value(&doc_context).unwrap(),
        );

        let result = verify_data(&invalid_context);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Document context does not match proof context".to_string(),
            ))
        );
    }

    #[test]
    fn valid_context() {
        let signed_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/2".to_string(),
        ];
        let mut invalid_context = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "Test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: Some(signed_context),
            }),
        };

        let doc_context = vec![
            "https://sample.com/3".to_string(),
            "https://example.com/1".to_string(),
            "https://example.com/2".to_string(),
        ];
        invalid_context.extra.insert(
            "@context".to_string(),
            serde_json::to_value(&doc_context).unwrap(),
        );

        let result = verify_data(&invalid_context);
        assert!(result.is_err());
        // Passed the context check test
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid proof type, expected 'DataIntegrityProof'".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_data_integrity_proof() {
        let invalid_data_integrity_proof = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "test".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: None,
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_data_integrity_proof);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid proof type, expected 'DataIntegrityProof'".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_crypto_suite() {
        // TODO: Need to add more crypto types in the future
    }

    #[test]
    fn invalid_created() {
        let invalid_create = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("not-a-date".to_string()),
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_create);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid created date: input contains invalid characters".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_created_future() {
        let invalid_create = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("3999-01-01T00:00:00Z".to_string()),
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_create);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Created date is in the future".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_verification_method() {
        let invalid_verification_method = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_verification_method);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Verification method must start with 'did:key:'".to_string(),
            ))
        );
    }

    #[test]
    fn invalid_verification_method_2() {
        let invalid_verification_method = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "did:key:not_a_key".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_verification_method);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid verification method format".to_string(),
            ))
        );
    }
    #[test]
    fn invalid_verification_method_3() {
        let invalid_verification_method = SignedDocument {
            extra: HashMap::new(),
            proof: Some(crate::DataIntegrityProof {
                type_: "DataIntegrityProof".to_string(),
                cryptosuite: CryptoSuite::EddsaJcs2022,
                created: Some("2025-01-01T00:00:00Z".to_string()),
                verification_method: "did:key:test#test".to_string(),
                proof_purpose: "test".to_string(),
                proof_value: Some("z2RPk8MWLoULfcbtpULoEsgfDsaAvyfD1PvQC2v3BjqqNtzGu8YJ4Nxq8CmJCZpPqA49uJhkxmxSztUQhBxqnVrYj".to_string()),
                context: None,
            }),
        };

        let result = verify_data(&invalid_verification_method);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::InputDataError(
                "Invalid public key: Key Error: Failed to multibase.decode key: Invalid base string".to_string(),
            ))
        );
    }

    #[test]
    fn failed_verification() {
        let invalid_signed = r#"{
  "parameters": {
    "deactivated": true,
    "method": "did:webvh:1.0",
    "next_key_hashes": [
      "zQmcTKbHERk1Q5QsUBnTbnhJhdwnSREyoS3duyLuPBWDUPA"
    ],
    "portable": true,
    "scid": "zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7",
    "update_keys": [
      "z6MkkkpnVE5PnEyJPLJ4GFdas8Grykt2L3E2gqCbK7ktui8v"
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
    }
  },
  "proof": {
    "created": "2025-06-01T00:05:34Z",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4y49Tm7xP5oGXoKyWdovvpkrRdVF3Fk8dxiSGuyWBy5cYLoabfiwtN68ZzDuHWYhdF8SpkJfgukcRLTZbmdqBbPt",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:key:z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm#z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm"
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
  },
  "version_id": "1-zQmW7ssogG8fwWBZTdH47S4vntYJzVB4vbXR1pYsAhriNh4",
  "version_time": "2025-05-31T02:11:02Z"
}"#;

        let invalid_signed: SignedDocument = serde_json::from_str(invalid_signed).unwrap();

        let result = verify_data(&invalid_signed);
        assert!(result.is_err());
        assert_eq!(
            result.err(),
            Some(DataIntegrityError::VerificationError(
                "Signature verification failed: Verification Error: Signature verification failed"
                    .to_string()
            ))
        );
    }

    #[test]
    fn verification_ok() {
        let signed = r#"{
  "parameters": {
    "deactivated": false,
    "method": "did:webvh:1.0",
    "next_key_hashes": [
      "zQmcTKbHERk1Q5QsUBnTbnhJhdwnSREyoS3duyLuPBWDUPA"
    ],
    "portable": true,
    "scid": "zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7",
    "update_keys": [
      "z6MkkkpnVE5PnEyJPLJ4GFdas8Grykt2L3E2gqCbK7ktui8v"
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
    }
  },
  "proof": {
    "created": "2025-06-01T00:05:34Z",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4y49Tm7xP5oGXoKyWdovvpkrRdVF3Fk8dxiSGuyWBy5cYLoabfiwtN68ZzDuHWYhdF8SpkJfgukcRLTZbmdqBbPt",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:key:z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm#z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm"
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
  },
  "version_id": "1-zQmW7ssogG8fwWBZTdH47S4vntYJzVB4vbXR1pYsAhriNh4",
  "version_time": "2025-05-31T02:11:02Z"
}"#;
        let signed: SignedDocument = serde_json::from_str(signed).unwrap();

        let result = verify_data(&signed);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.verified);
    }

    #[test]
    fn verification_ok_changed_order() {
        let signed = r#"{
  "parameters": {
    "method": "did:webvh:1.0",
    "deactivated": false,
    "next_key_hashes": [
      "zQmcTKbHERk1Q5QsUBnTbnhJhdwnSREyoS3duyLuPBWDUPA"
    ],
    "scid": "zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7",
    "portable": true,
    "update_keys": [
      "z6MkkkpnVE5PnEyJPLJ4GFdas8Grykt2L3E2gqCbK7ktui8v"
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
    }
  },
  "proof": {
    "created": "2025-06-01T00:05:34Z",
    "cryptosuite": "eddsa-jcs-2022",
    "proofPurpose": "assertionMethod",
    "proofValue": "z4y49Tm7xP5oGXoKyWdovvpkrRdVF3Fk8dxiSGuyWBy5cYLoabfiwtN68ZzDuHWYhdF8SpkJfgukcRLTZbmdqBbPt",
    "type": "DataIntegrityProof",
    "verificationMethod": "did:key:z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm#z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm"
  },
  "state": {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://www.w3.org/ns/cid/v1"
    ],
    "service": [],
    "authentication": [
      "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
    ],
    "assertionMethod": [
      "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
    ],
    "capabilityDelegation": [],
    "capabilityInvocation": [],
    "id": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000",
    "keyAgreement": [
      "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0"
    ],
    "verificationMethod": [
      {
        "controller": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000",
        "id": "did:webvh:zQmQNi9ZDiNEAxkyLrjHjFFsSgb8fAs3P6bfwJhYbojVnB7:localhost%3A8000#key-0",
        "publicKeyMultibase": "z6Mkn6Rwmuzpc8wvErSX4WbDW4Cu3XVtbdRV9fGdb2hea4Fs",
        "type": "Multikey"
      }
    ]
  },
  "version_time": "2025-05-31T02:11:02Z",
  "version_id": "1-zQmW7ssogG8fwWBZTdH47S4vntYJzVB4vbXR1pYsAhriNh4"
}"#;
        let signed: SignedDocument = serde_json::from_str(signed).unwrap();

        let result = verify_data(&signed);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.verified);
    }
}
