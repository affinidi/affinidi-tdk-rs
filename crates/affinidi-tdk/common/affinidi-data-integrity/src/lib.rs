use affinidi_tdk_common::{TDKSharedState, secrets_resolver::SecretsResolver};
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

    #[serde(rename = "@context", skip_serializing_if = "Vec::is_empty")]
    pub context: Vec<String>,
}

/// Creates a signature for the given data using the specified key.
/// data_doc: An object that can be serialized to JSON.
///
/// Returns a Result containing the signature as a String or an error.
pub async fn sign_data_jcs<D>(
    tdk: &TDKSharedState,
    data_doc: &D,
    vm_id: &str,
) -> Result<Value, DataIntegrityError>
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
    debug!(
        "CryptoSuite: {}",
        <CryptoSuite as TryInto<String>>::try_into(crypto_suite.clone()).unwrap()
    );
    // final doc
    let mut signed_doc: Value = serde_json::to_value(data_doc).unwrap();
    let context: Vec<String> = if let Some(context) = signed_doc.get("@context") {
        serde_json::from_value(context.to_owned()).unwrap()
    } else {
        Vec::new()
    };

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
    let mut jcs_hash = Sha256::digest(jcs).to_vec();
    debug!("JCS Hash: {:02x?}", &jcs_hash);

    // Step 3: Create a Proof Options struct
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
    debug!("{}", proof_jcs);

    // Step 4: Create a SHA-256 hash of the canonical proof options string
    let mut proof_hash = Sha256::digest(proof_jcs).to_vec();
    debug!("Proof Hash: {:02x?}", &proof_hash);

    // Step 5: Combine hashes
    proof_hash.append(&mut jcs_hash);

    // Step 6: Sign the final hash
    let signed = crypto_suite.sign(&secret, proof_hash.as_slice())?;
    debug!("{}", format!("signed: {:02x?}", &signed));

    // Step 7: Encode using base58btc
    proof_options.proof_value = Some(MultibaseBuf::encode(Base::Base58Btc, &signed).to_string());
    signed_doc["proof"] = serde_json::to_value(proof_options).unwrap();

    Ok(signed_doc)
}
