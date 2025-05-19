use crypto_suites::CryptoSuite;
use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_string;
use thiserror::Error;

pub mod crypto_suites;

/// Affinidi Data Integrity Library Errors
#[derive(Error, Debug)]
pub enum DataIntegrityError {
    #[error("Input Data Error: {0}")]
    InputDataError(String),
    #[error("Crypto Error: {0}")]
    CryptoError(String),
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
pub fn sign_data_jcs<D>(data_doc: &D) -> Result<String, DataIntegrityError>
where
    D: Serialize,
{
    Ok(to_string(data_doc).unwrap())
}
