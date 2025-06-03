use std::collections::HashMap;

use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use crypto_suites::CryptoSuite;
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use ssi::security::MultibaseBuf;
use thiserror::Error;
use tracing::debug;

pub mod crypto_suites;
pub mod verification_proof;

/// Affinidi Data Integrity Library Errors
#[derive(Error, Debug, PartialEq)]
pub enum DataIntegrityError {
    #[error("Input Data Error: {0}")]
    InputDataError(String),
    #[error("Crypto Error: {0}")]
    CryptoError(String),
    #[error("Secrets Error: {0}")]
    SecretsError(String),
    #[error("Verification Error: {0}")]
    VerificationError(String),
}

/// Generic Document structure that can be used for converting any Serializable document
/// into a format this library can understand.
/// Works with both signed and unsigned Documents.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GenericDocument {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<DataIntegrityProof>,

    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DataIntegrityProof {
    /// Must be 'DataIntegrityProof'
    #[serde(rename = "type")]
    pub type_: String,

    pub cryptosuite: CryptoSuite,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    pub verification_method: String,

    pub proof_purpose: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_value: Option<String>,

    #[serde(rename = "@context", skip_serializing_if = "Option::is_none")]
    pub context: Option<Vec<String>>,
}

impl DataIntegrityProof {
    /// Creates a signature for the given data using the specified key.
    /// data_doc: JSON Schema
    ///
    /// Returns a Result containing a signed document
    pub fn sign_data_jcs(
        data_doc: &GenericDocument,
        vm_id: &str,
        secret: &Secret,
    ) -> Result<Value, DataIntegrityError> {
        // Initialise as required
        let crypto_suite: CryptoSuite = secret.get_key_type().try_into()?;
        debug!(
            "CryptoSuite: {}",
            <CryptoSuite as TryInto<String>>::try_into(crypto_suite.clone()).unwrap()
        );

        // final doc
        let mut signed_doc = data_doc.clone();
        let context: Option<Vec<String>> = signed_doc
            .extra
            .get("@context")
            .map(|context| serde_json::from_value(context.to_owned()).unwrap());

        // Step 1: Serialize the data document to a canonical JSON string
        let jcs = match to_string(data_doc) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize data document: {}",
                    e
                )));
            }
        };
        debug!("Document: {}", jcs);

        // Create a Proof Options struct
        let now = Utc::now();
        let mut proof_options = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: crypto_suite.clone(),
            created: Some(now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            verification_method: vm_id.to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            context,
        };

        let proof_jcs = match to_string(&proof_options) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize proof options: {}",
                    e
                )));
            }
        };
        debug!("proof options: {}", proof_jcs);

        let hash_data = hashing_eddsa_jcs(&jcs, &proof_jcs);

        // Step 6: Sign the final hash
        let signed = crypto_suite.sign(secret, hash_data.as_slice())?;
        debug!("{}", format!("signed: {:02x?}", &signed));

        // Step 7: Encode using base58btc
        proof_options.proof_value =
            Some(MultibaseBuf::encode(Base::Base58Btc, &signed).to_string());
        signed_doc.extra.insert(
            "proof".to_string(),
            serde_json::to_value(proof_options).unwrap(),
        );

        serde_json::to_value(&signed_doc).map_err(|e| {
            DataIntegrityError::InputDataError(format!(
                "Failed to serialize signed document: {}",
                e
            ))
        })
    }
}

/// Hashing Algorithm for EDDSA JCS
fn hashing_eddsa_jcs(transformed_document: &str, canonical_proof_config: &str) -> Vec<u8> {
    [
        Sha256::digest(canonical_proof_config),
        Sha256::digest(transformed_document),
    ]
    .concat()
}

#[cfg(test)]
mod tests {
    use affinidi_secrets_resolver::secrets::Secret;
    use serde_json::json;

    use crate::{DataIntegrityProof, GenericDocument, hashing_eddsa_jcs};

    #[test]
    fn hashing_working() {
        let hash = hashing_eddsa_jcs("test1", "test2");
        let mut output = String::new();
        for x in hash {
            output.push_str(&format!("{:02x}", x));
        }

        assert_eq!(
            output.as_str(),
            "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c7521b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014",
        );
    }

    #[test]
    fn test_sign_data_jcs_bad_key() {
        let generic_doc: GenericDocument = serde_json::from_value(json!({"test": "test_data"}))
            .expect("Couldn't deserialize test data");

        let pub_key = "zruqgFba156mDWfMUjJUSAKUvgCgF5NfgSYwSuEZuXpixts8tw3ot5BasjeyM65f8dzk5k6zgXf7pkbaaBnPrjCUmcJ";
        let pri_key = "z42tmXtqqQBLmEEwn8tfi1bA2ghBx9cBo6wo8a44kVJEiqyA";
        let secret = Secret::from_multibase(
            &format!("did:key:{}#{}", pub_key, pub_key),
            pub_key,
            pri_key,
        )
        .expect("Couldn't create test key data");

        assert!(DataIntegrityProof::sign_data_jcs(&generic_doc, &secret.id, &secret).is_err());
    }
    #[test]
    fn test_sign_data_jcs_good() {
        let generic_doc: GenericDocument = serde_json::from_value(
            json!({"test": "test_data", "@context": ["context1", "context2", "context3"]}),
        )
        .expect("Couldn't deserialize test data");

        let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
        let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";
        let secret = Secret::from_multibase(
            &format!("did:key:{}#{}", pub_key, pub_key),
            pub_key,
            pri_key,
        )
        .expect("Couldn't create test key data");

        assert!(
            DataIntegrityProof::sign_data_jcs(&generic_doc, &secret.id, &secret).is_ok(),
            "Signing failed"
        );
    }
}
