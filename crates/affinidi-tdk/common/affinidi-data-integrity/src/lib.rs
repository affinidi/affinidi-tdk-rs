/*!
*   W3C Data Integrity Implementation
*/

use affinidi_secrets_resolver::secrets::Secret;
use chrono::Utc;
use crypto_suites::CryptoSuite;
use multibase::Base;
use serde::{Deserialize, Serialize};
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
    /// data_doc: Serializable Struct
    /// context: Optional context for the proof
    /// secret: Secret containing the private key to sign with
    /// created: Optional timestamp for the proof creation ("2023-02-24T23:36:38Z")
    ///
    /// Returns a Result containing a proof if successfull
    pub fn sign_jcs_data<S>(
        data_doc: &S,
        context: Option<Vec<String>>,
        secret: &Secret,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        // Initialise as required
        let crypto_suite: CryptoSuite = secret.get_key_type().try_into()?;
        debug!(
            "CryptoSuite: {}",
            <CryptoSuite as TryInto<String>>::try_into(crypto_suite.clone()).unwrap()
        );

        // Step 1: Serialize the data document to a canonical JSON string
        let jcs = match to_string(data_doc) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize data document: {e}",
                )));
            }
        };
        debug!("Document: {}", jcs);

        let created = if created.is_some() {
            created
        } else {
            Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        };

        // Create a Proof Options struct
        let mut proof_options = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: crypto_suite.clone(),
            created,
            verification_method: secret.id.clone(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            context,
        };

        let proof_jcs = match to_string(&proof_options) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize proof options: {e}",
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

        Ok(proof_options)
    }

    pub fn sign_jcs_proof_only<S>(
        data_doc: &S,
        context: Option<Vec<String>>,
        secret: &Secret,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        // Initialise as required
        let crypto_suite: CryptoSuite = secret.get_key_type().try_into()?;
        debug!(
            "CryptoSuite: {}",
            <CryptoSuite as TryInto<String>>::try_into(crypto_suite.clone()).unwrap()
        );

        // final doc

        // Step 1: Serialize the data document to a canonical JSON string
        let jcs = match to_string(data_doc) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize data document: {e}",
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
            verification_method: secret.id.clone(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            context,
        };

        let proof_jcs = match to_string(&proof_options) {
            Ok(jcs) => jcs,
            Err(e) => {
                return Err(DataIntegrityError::InputDataError(format!(
                    "Failed to serialize proof options: {e}",
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

        Ok(proof_options)
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

    use crate::{DataIntegrityProof, hashing_eddsa_jcs};

    #[test]
    fn hashing_working() {
        let hash = hashing_eddsa_jcs("test1", "test2");
        let mut output = String::new();
        for x in hash {
            output.push_str(&format!("{x:02x}"));
        }

        assert_eq!(
            output.as_str(),
            "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c7521b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014",
        );
    }

    #[test]
    fn test_sign_jcs_data_bad_key() {
        let generic_doc = json!({"test": "test_data"});

        let pub_key = "zruqgFba156mDWfMUjJUSAKUvgCgF5NfgSYwSuEZuXpixts8tw3ot5BasjeyM65f8dzk5k6zgXf7pkbaaBnPrjCUmcJ";
        let pri_key = "z42tmXtqqQBLmEEwn8tfi1bA2ghBx9cBo6wo8a44kVJEiqyA";
        let secret =
            Secret::from_multibase(&format!("did:key:{pub_key}#{pub_key}"), pub_key, pri_key)
                .expect("Couldn't create test key data");

        assert!(DataIntegrityProof::sign_jcs_data(&generic_doc, None, &secret, None).is_err());
    }

    #[test]
    fn test_sign_jcs_data_good() {
        let generic_doc = json!({"test": "test_data"});

        let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
        let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";
        let secret =
            Secret::from_multibase(&format!("did:key:{pub_key}#{pub_key}"), pub_key, pri_key)
                .expect("Couldn't create test key data");

        let context = vec![
            "context1".to_string(),
            "context2".to_string(),
            "context3".to_string(),
        ];
        assert!(
            DataIntegrityProof::sign_jcs_data(&generic_doc, Some(context), &secret, None).is_ok(),
            "Signing failed"
        );
    }

    #[test]
    fn test_sign_jcs_proof_only_good() {
        let generic_doc =
            json!({"test": "test_data", "@context": ["context1", "context2", "context3"]});

        let context: Vec<String> = generic_doc
            .get("@context")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_string())
            .collect();

        let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
        let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";
        let secret =
            Secret::from_multibase(&format!("did:key:{pub_key}#{pub_key}"), pub_key, pri_key)
                .expect("Couldn't create test key data");

        assert!(
            DataIntegrityProof::sign_jcs_proof_only(&generic_doc, Some(context), &secret).is_ok(),
            "Signing failed"
        );
    }
}
