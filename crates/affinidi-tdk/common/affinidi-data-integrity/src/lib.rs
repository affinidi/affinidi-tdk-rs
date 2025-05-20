use affinidi_tdk_common::{TDKSharedState, secrets_resolver::SecretsResolver};
use crypto_suites::CryptoSuite;
use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::debug;

pub mod crypto_suites;

/// Affinidi Data Integrity Library Errors
#[derive(Error, Debug)]
pub enum DataIntegrityError {
    #[error("Input Data Error: {0}")]
    InputDataError(String),
    #[error("Crypto Error: {0}")]
    CryptoError(String),
    #[error("Secrets Error: {0}")]
    SecretsError(String),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DataIntegrityProof {
    /// Must be 'DataIntegrityProof'
    #[serde(rename = "type")]
    pub type_: String,

    #[serde(rename = "cryptosuite")]
    pub cryptosuite: CryptoSuite,

    pub created: String,

    pub verification_method: String,

    pub proof_purpose: String,

    pub proof_value: String,
}

/// Proof options
pub struct ProofOptions {
    pub type_: CryptoSuite,
}

/// Creates a signature for the given data using the specified key.
/// data_doc: An object that can be serialized to JSON.
///
/// Returns a Result containing the signature as a String or an error.
pub async fn sign_data_jcs<D>(
    tdk: &TDKSharedState,
    data_doc: &D,
    vm_id: &str,
) -> Result<String, DataIntegrityError>
where
    D: Serialize,
{
    // Initialise as required
    let Some(secret) = tdk.secrets_resolver.get_secret(vm_id).await else {
        return Err(DataIntegrityError::SecretsError(format!(
            "Cannot find secret for {}",
            vm_id
        )));
    };
    let crypto_suite: CryptoSuite = secret.get_key_type().try_into()?;
    debug!("CryptoSuite: {:?}", crypto_suite);

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

    // Step 2: Create a SHA-256 hash of the canonical JSON string
    let jcs_hash = format!("{:02x}", Sha256::digest(jcs));
    debug!("JCS Hash: {}", jcs_hash);

    Ok(jcs_hash)
}
