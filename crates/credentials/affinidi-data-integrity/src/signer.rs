/*!
*   Signer trait for abstracting signing operations.
*
*   Allows pluggable signing backends: local keys (ed25519-dalek),
*   external KMS (AWS KMS, Azure Key Vault), or HSM devices.
*/

use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};

use crate::DataIntegrityError;

/// Trait for abstracting the signing operation.
///
/// Implementations can sign locally using in-memory key material,
/// or delegate to external services (KMS, HSM) via async I/O.
#[async_trait]
pub trait Signer: Send + Sync {
    /// The key type this signer uses (for cryptosuite validation).
    fn key_type(&self) -> KeyType;

    /// The verification method URI (e.g. `did:key:z6Mk...#z6Mk...`) for proof metadata.
    fn verification_method(&self) -> &str;

    /// Sign the provided data, returning the raw signature bytes.
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError>;
}

/// Blanket implementation for `Secret`, providing local Ed25519 signing
/// via ed25519-dalek. Existing callers can continue passing `&secret` directly.
#[async_trait]
impl Signer for Secret {
    fn key_type(&self) -> KeyType {
        self.get_key_type()
    }

    fn verification_method(&self) -> &str {
        &self.id
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError> {
        match self.get_key_type() {
            KeyType::Ed25519 => {
                let private_bytes: [u8; 32] =
                    self.get_private_bytes().try_into().map_err(|_| {
                        DataIntegrityError::CryptoError("Invalid Ed25519 private key length".into())
                    })?;
                let mut signing_key = SigningKey::from_bytes(&private_bytes);
                Ok(signing_key.sign(data).to_vec())
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa44 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_44(self.get_private_bytes(), data).map_err(
                    |e| DataIntegrityError::CryptoError(format!("ML-DSA-44 sign failed: {e}")),
                )
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa65 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_65(self.get_private_bytes(), data).map_err(
                    |e| DataIntegrityError::CryptoError(format!("ML-DSA-65 sign failed: {e}")),
                )
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa87 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_87(self.get_private_bytes(), data).map_err(
                    |e| DataIntegrityError::CryptoError(format!("ML-DSA-87 sign failed: {e}")),
                )
            }
            #[cfg(feature = "slh-dsa")]
            KeyType::SlhDsaSha2_128s => {
                affinidi_crypto::slh_dsa::sign_slh_dsa_sha2_128s(self.get_private_bytes(), data)
                    .map_err(|e| {
                        DataIntegrityError::CryptoError(format!("SLH-DSA sign failed: {e}"))
                    })
            }
            other => Err(DataIntegrityError::CryptoError(format!(
                "Signer for key type {other:?} is not implemented"
            ))),
        }
    }
}
