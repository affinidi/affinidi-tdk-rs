//! Signer trait for abstracting signing operations.
//!
//! Implementations can sign locally using in-memory key material, or
//! delegate to external services (KMS, HSM, cloud key vaults) via async
//! I/O. Remote signers implement exactly the same trait as local ones —
//! there is no second-class citizen.
//!
//! # Contract
//!
//! A `Signer` is responsible for producing the raw signature bytes over
//! the *pre-hash* input the data-integrity pipeline hands to it. The
//! pipeline is:
//!
//! 1. Canonicalize the document (JCS or RDFC, determined by cryptosuite).
//! 2. Canonicalize the proof config (same algorithm).
//! 3. Hash each with SHA-256 and concatenate (`proof_hash || doc_hash`).
//! 4. Hand those 64 bytes to [`Signer::sign`].
//!
//! A remote signer must sign exactly those 64 bytes. The library-provided
//! [`crate::prepare_sign_input`] helper returns that byte slice ahead of
//! time for remote-signing protocols that need it.

use affinidi_secrets_resolver::secrets::{KeyType, Secret};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, ed25519::signature::SignerMut};

use crate::DataIntegrityError;
use crate::crypto_suites::CryptoSuite;

/// Trait for abstracting the signing operation.
///
/// Implementations can sign locally using in-memory key material, or
/// delegate to external services (KMS, HSM) via async I/O.
///
/// # Cryptosuite selection
///
/// Every signer declares the cryptosuite it produces via
/// [`Signer::cryptosuite`]. The default implementation picks the
/// recommended default suite for the signer's key type (e.g.
/// `eddsa-jcs-2022` for Ed25519 keys, `mldsa44-jcs-2024` for ML-DSA-44).
/// Signers that want a non-default variant (RDFC canonicalization, a
/// hybrid scheme, a future suite) override this method.
///
/// Callers who want to force a specific suite for one sign call without
/// changing the signer's default can pass
/// [`crate::SignOptions::with_cryptosuite`].
#[async_trait]
pub trait Signer: Send + Sync {
    /// The key type this signer uses (for cryptosuite validation).
    fn key_type(&self) -> KeyType;

    /// The verification method URI (e.g. `did:key:z6Mk...#z6Mk...`) for
    /// proof metadata.
    fn verification_method(&self) -> &str;

    /// Sign the provided data, returning the raw signature bytes.
    ///
    /// The caller is expected to hand pre-hashed, pre-canonicalised bytes
    /// in exactly the format the cryptosuite expects (see the module
    /// docs). Errors should be wrapped in
    /// [`DataIntegrityError::signing`] so the source chain is preserved.
    #[must_use = "ignoring a sign result silently drops the produced signature"]
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, DataIntegrityError>;

    /// The default cryptosuite this signer produces.
    ///
    /// The default implementation derives the suite from the signer's key
    /// type via [`CryptoSuite::default_for_key_type`] (which prefers JCS
    /// over RDFC). Override when you want a different default, e.g. a
    /// signer tied to RDFC-canonicalized VCs, or a future hybrid scheme.
    ///
    /// Falls back to [`CryptoSuite::EddsaJcs2022`] for key types that
    /// have no compiled-in suite — callers must then override via
    /// [`crate::SignOptions::with_cryptosuite`] or the library will error
    /// with a key-type mismatch.
    fn cryptosuite(&self) -> CryptoSuite {
        CryptoSuite::default_for_key_type(self.key_type()).unwrap_or(CryptoSuite::EddsaJcs2022)
    }
}

/// Blanket implementation for `Secret`, providing local signing via
/// `ed25519-dalek` / `ml-dsa` / `slh-dsa` depending on the key type.
/// Existing callers can continue passing `&secret` directly.
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
                        DataIntegrityError::InvalidPublicKey {
                            codec: None,
                            len: self.get_private_bytes().len(),
                            reason: "Ed25519 private key must be exactly 32 bytes".to_string(),
                        }
                    })?;
                let mut signing_key = SigningKey::from_bytes(&private_bytes);
                Ok(signing_key.sign(data).to_vec())
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa44 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_44(self.get_private_bytes(), data)
                    .map_err(DataIntegrityError::signing)
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa65 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_65(self.get_private_bytes(), data)
                    .map_err(DataIntegrityError::signing)
            }
            #[cfg(feature = "ml-dsa")]
            KeyType::MlDsa87 => {
                affinidi_crypto::ml_dsa::sign_ml_dsa_87(self.get_private_bytes(), data)
                    .map_err(DataIntegrityError::signing)
            }
            #[cfg(feature = "slh-dsa")]
            KeyType::SlhDsaSha2_128s => {
                affinidi_crypto::slh_dsa::sign_slh_dsa_sha2_128s(self.get_private_bytes(), data)
                    .map_err(DataIntegrityError::signing)
            }
            other => Err(DataIntegrityError::UnsupportedCryptoSuite {
                name: format!("(no signer compiled in for key type {other:?})"),
            }),
        }
    }
}
