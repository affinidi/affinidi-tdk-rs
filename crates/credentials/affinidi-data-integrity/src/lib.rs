/*!
*   W3C Data Integrity Implementation
*/

use chrono::Utc;
use crypto_suites::CryptoSuite;
use multibase::Base;
use serde::{Deserialize, Serialize};
use serde_json_canonicalizer::to_string;
use sha2::{Digest, Sha256};
use signer::Signer;
use thiserror::Error;
use tracing::debug;

pub mod crypto_suites;
pub mod signer;
pub mod verification_proof;

/// BBS-2023 Data Integrity Cryptosuite for zero-knowledge selective disclosure.
///
/// Enabled via the `bbs-2023` feature flag.
#[cfg(feature = "bbs-2023")]
pub mod bbs_2023;

/// Affinidi Data Integrity Library Errors
#[derive(Error, Debug)]
pub enum DataIntegrityError {
    #[error("Input Data Error: {0}")]
    InputDataError(String),
    #[error("Crypto Error: {0}")]
    CryptoError(String),
    #[error("Secrets Error: {0}")]
    SecretsError(String),
    #[error("Verification Error: {0}")]
    VerificationError(String),
    #[error("RDF Encoding Error: {0}")]
    RdfEncodingError(String),
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
    /// Creates a JCS (JSON Canonicalization Scheme) signature for the given data.
    /// data_doc: Serializable Struct
    /// context: Optional context for the proof
    /// signer: Implementation of the Signer trait (e.g. a Secret, or a KMS/HSM backend)
    /// created: Optional timestamp for the proof creation ("2023-02-24T23:36:38Z")
    ///
    /// Returns a Result containing a proof if successful
    pub async fn sign_jcs_data<S>(
        data_doc: &S,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::EddsaJcs2022,
            data_doc,
            context,
            signer,
            created,
        )
        .await
    }

    /// Creates a JCS signature with an explicit cryptosuite. Use this to sign
    /// with post-quantum suites (`mldsa44-jcs-2024`, `slhdsa128-jcs-2024`).
    pub async fn sign_jcs_data_with_suite<S>(
        crypto_suite: CryptoSuite,
        data_doc: &S,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError>
    where
        S: Serialize,
    {
        if crypto_suite.is_rdfc() {
            return Err(DataIntegrityError::InputDataError(format!(
                "Cryptosuite {} uses RDFC canonicalization; call sign_rdfc_data_with_suite instead",
                String::try_from(crypto_suite).unwrap_or_default()
            )));
        }
        crypto_suite.validate_key_type(signer.key_type())?;
        debug!(
            "CryptoSuite: {}",
            <CryptoSuite as TryInto<String>>::try_into(crypto_suite).unwrap()
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
            cryptosuite: crypto_suite,
            created,
            verification_method: signer.verification_method().to_string(),
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
        debug!("proof options (JCS): {}", proof_jcs);

        let hash_data = hashing_eddsa_jcs(&jcs, &proof_jcs);

        // Step 6: Sign the final hash
        let signed = signer.sign(hash_data.as_slice()).await?;
        debug!(
            "signature data = {}",
            signed
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join("")
        );

        // Step 7: Encode using base58btc
        proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed).to_string());

        Ok(proof_options)
    }

    /// Creates an RDFC (RDF Dataset Canonicalization) signature for the given JSON-LD data.
    /// data_doc: JSON-LD document (must contain `@context`)
    /// context: Optional context override for the proof; if None, uses the document's `@context`
    /// signer: Implementation of the Signer trait (e.g. a Secret, or a KMS/HSM backend)
    /// created: Optional timestamp for the proof creation ("2023-02-24T23:36:38Z")
    ///
    /// Returns a Result containing a proof if successful
    pub async fn sign_rdfc_data(
        data_doc: &serde_json::Value,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError> {
        DataIntegrityProof::sign_rdfc_data_with_suite(
            CryptoSuite::EddsaRdfc2022,
            data_doc,
            context,
            signer,
            created,
        )
        .await
    }

    /// Creates an RDFC signature with an explicit cryptosuite. Use this to sign
    /// with post-quantum suites (`mldsa44-rdfc-2024`, `slhdsa128-rdfc-2024`).
    pub async fn sign_rdfc_data_with_suite(
        crypto_suite: CryptoSuite,
        data_doc: &serde_json::Value,
        context: Option<Vec<String>>,
        signer: &dyn Signer,
        created: Option<String>,
    ) -> Result<DataIntegrityProof, DataIntegrityError> {
        if !crypto_suite.is_rdfc() {
            return Err(DataIntegrityError::InputDataError(format!(
                "Cryptosuite {} uses JCS canonicalization; call sign_jcs_data_with_suite instead",
                String::try_from(crypto_suite).unwrap_or_default()
            )));
        }
        crypto_suite.validate_key_type(signer.key_type())?;
        debug!(
            "CryptoSuite: {}",
            <CryptoSuite as TryInto<String>>::try_into(crypto_suite).unwrap()
        );

        // Extract @context from document (required for JSON-LD)
        let doc_context = data_doc
            .get("@context")
            .ok_or_else(|| {
                DataIntegrityError::InputDataError(
                    "Document must contain @context for RDFC signing".to_string(),
                )
            })?
            .clone();

        // Use provided context or extract from document
        let proof_context = if let Some(ctx) = context {
            ctx
        } else {
            match &doc_context {
                serde_json::Value::Array(arr) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
                serde_json::Value::String(s) => vec![s.clone()],
                _ => {
                    return Err(DataIntegrityError::InputDataError(
                        "Invalid @context format in document".to_string(),
                    ));
                }
            }
        };

        let created = if created.is_some() {
            created
        } else {
            Some(Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        };

        // Create proof options (without proof_value)
        let mut proof_options = DataIntegrityProof {
            type_: "DataIntegrityProof".to_string(),
            cryptosuite: crypto_suite,
            created,
            verification_method: signer.verification_method().to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: None,
            context: Some(proof_context),
        };

        // Serialize proof options to Value for RDFC pipeline
        let proof_value = serde_json::to_value(&proof_options).map_err(|e| {
            DataIntegrityError::InputDataError(format!("Failed to serialize proof options: {e}"))
        })?;

        let hash_data = hashing_eddsa_rdfc(data_doc, &proof_value)?;

        // Sign the final hash
        let signed = signer.sign(hash_data.as_slice()).await?;
        debug!(
            "signature data = {}",
            signed
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<String>>()
                .join("")
        );

        // Encode using base58btc
        proof_options.proof_value = Some(multibase::encode(Base::Base58Btc, &signed).to_string());

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

/// Hashing Algorithm for EDDSA RDFC
/// Runs both document and proof config through the RDFC pipeline
/// (JSON-LD expansion → RDF Dataset → RDFC-1.0 canonicalization → SHA-256)
/// and concatenates the two 32-byte hashes.
fn hashing_eddsa_rdfc(
    document: &serde_json::Value,
    proof_config: &serde_json::Value,
) -> Result<Vec<u8>, DataIntegrityError> {
    let doc_hash = affinidi_rdf_encoding::expand_canonicalize_and_hash(document).map_err(|e| {
        DataIntegrityError::RdfEncodingError(format!("Failed to hash document: {e}"))
    })?;

    let proof_hash =
        affinidi_rdf_encoding::expand_canonicalize_and_hash(proof_config).map_err(|e| {
            DataIntegrityError::RdfEncodingError(format!("Failed to hash proof config: {e}"))
        })?;

    Ok([proof_hash.as_slice(), doc_hash.as_slice()].concat())
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

    #[tokio::test]
    async fn test_sign_jcs_data_bad_key() {
        let generic_doc = json!({"test": "test_data"});

        let pub_key = "zruqgFba156mDWfMUjJUSAKUvgCgF5NfgSYwSuEZuXpixts8tw3ot5BasjeyM65f8dzk5k6zgXf7pkbaaBnPrjCUmcJ";
        let pri_key = "z42tmXtqqQBLmEEwn8tfi1bA2ghBx9cBo6wo8a44kVJEiqyA";
        let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
            .expect("Couldn't create test key data");

        assert!(
            DataIntegrityProof::sign_jcs_data(&generic_doc, None, &secret, None)
                .await
                .is_err()
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_ml_dsa_44() {
        use crate::{crypto_suites::CryptoSuite, verification_proof::verify_data_with_public_key};

        let secret = Secret::generate_ml_dsa_44(Some("k-did#k-did"), Some(&[5u8; 32]));
        let doc = json!({"hello": "pqc"});

        let proof = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::MlDsa44Jcs2024,
            &doc,
            None,
            &secret,
            None,
        )
        .await
        .expect("sign ml-dsa");

        assert_eq!(proof.cryptosuite, CryptoSuite::MlDsa44Jcs2024);

        let result = verify_data_with_public_key(&doc, None, &proof, secret.get_public_bytes())
            .expect("verify ml-dsa");
        assert!(result.verified);
    }

    #[cfg(feature = "ml-dsa")]
    #[tokio::test]
    async fn sign_wrong_suite_for_key_fails() {
        use crate::crypto_suites::CryptoSuite;

        let secret = Secret::generate_ml_dsa_44(Some("k"), Some(&[1u8; 32]));
        let doc = json!({"x": 1});
        let err = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::EddsaJcs2022,
            &doc,
            None,
            &secret,
            None,
        )
        .await;
        assert!(err.is_err());
    }

    #[cfg(feature = "slh-dsa")]
    #[tokio::test]
    async fn sign_verify_jcs_slh_dsa_128s() {
        use crate::{crypto_suites::CryptoSuite, verification_proof::verify_data_with_public_key};

        let secret = Secret::generate_slh_dsa_sha2_128s(Some("k#k"));
        let doc = json!({"hello": "slh"});

        let proof = DataIntegrityProof::sign_jcs_data_with_suite(
            CryptoSuite::SlhDsa128Jcs2024,
            &doc,
            None,
            &secret,
            None,
        )
        .await
        .expect("sign slh-dsa");

        let result = verify_data_with_public_key(&doc, None, &proof, secret.get_public_bytes())
            .expect("verify slh-dsa");
        assert!(result.verified);
    }

    #[tokio::test]
    async fn test_sign_jcs_data_good() {
        let generic_doc = json!({"test": "test_data"});

        let pub_key = "z6MktDNePDZTvVcF5t6u362SsonU7HkuVFSMVCjSspQLDaBm";
        let pri_key = "z3u2UQyiY96d7VQaua8yiaSyQxq5Z5W5Qkpz7o2H2pc9BkEa";
        let secret = Secret::from_multibase(pri_key, Some(&format!("did:key:{pub_key}#{pub_key}")))
            .expect("Couldn't create test key data");

        let context = vec![
            "context1".to_string(),
            "context2".to_string(),
            "context3".to_string(),
        ];
        assert!(
            DataIntegrityProof::sign_jcs_data(&generic_doc, Some(context), &secret, None)
                .await
                .is_ok(),
            "Signing failed"
        );
    }
}
