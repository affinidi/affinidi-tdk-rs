//! Ed25519 signing and verification (EdDSA / JWS `alg: EdDSA`).
//!
//! Ported verbatim from `affinidi-messaging-didcomm` for the #327
//! centralization; byte-level output is locked by [`super::kat`].

use ed25519_dalek::{Signer, Verifier};

use crate::error::CryptoError;

/// Sign data with an Ed25519 private key (32-byte seed → 64-byte sig).
pub fn sign(data: &[u8], private_key: &[u8; 32]) -> Result<[u8; 64], CryptoError> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
pub fn verify(data: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> Result<(), CryptoError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::Verification(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify(data, &sig)
        .map_err(|e| CryptoError::Verification(format!("signature verification failed: {e}")))
}

/// Derive the Ed25519 public key from a private key.
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}
