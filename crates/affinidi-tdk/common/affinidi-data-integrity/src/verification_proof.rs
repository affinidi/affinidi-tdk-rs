use affinidi_secrets_resolver::secrets::Secret;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use ssi::security::MultibaseBuf;

use crate::{
    DataIntegrityError, DataIntegrityProof, GenericDocument, crypto_suites::CryptoSuite,
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
pub fn verify_data(signed_doc: &GenericDocument) -> Result<VerificationProof, DataIntegrityError> {
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
    let jcs_doc = to_string(&validation_doc).map_err(|e| {
        DataIntegrityError::InputDataError(format!("Failed to canonicalize document: {}", e))
    })?;

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

    verification_proof_result.verified_document =
        Some(serde_json::to_value(&signed_doc.extra).map_err(|e| {
            DataIntegrityError::InputDataError(format!("Failed to serialize document: {}", e))
        })?);

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
