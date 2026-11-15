//! Ed25519 signing/verification (EdDSA / JWS `alg: EdDSA`), ECDSA P-256
//! verification (JWS `alg: ES256`), and ECDSA secp256k1 verification (JWS
//! `alg: ES256K`).
//!
//! Ported verbatim from `affinidi-messaging-didcomm` for the #327
//! centralization; byte-level output is locked by [`super::kat`] (both the
//! Ed25519 and the deterministic-ECDSA P-256 golden vectors).

use ed25519_dalek::Signer;

use crate::error::CryptoError;

/// Sign data with an Ed25519 private key (32-byte seed → 64-byte sig).
pub fn sign(data: &[u8], private_key: &[u8; 32]) -> Result<[u8; 64], CryptoError> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature (JWS `alg: EdDSA`).
///
/// Uses `ed25519-dalek`'s `verify_strict`, the one Ed25519 policy across the
/// workspace (data-integrity, TSP, OpenID4VC and mdoc verify the same way):
/// it refuses signatures whose `R` is a small-order point and public keys of
/// small order, which plain `verify` accepts. A signature made by any
/// conforming signer (RFC 8032) passes both; only crafted, malleable
/// signatures are refused (#1143).
pub fn verify(data: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> Result<(), CryptoError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::Verification(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify_strict(data, &sig)
        .map_err(|e| CryptoError::Verification(format!("signature verification failed: {e}")))
}

/// Derive the Ed25519 public key from a private key.
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

/// Verify an ECDSA P-256 signature (JWS `alg: ES256`).
pub fn verify_p256(
    data: &[u8],
    signature: &[u8; 64],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    use p256::ecdsa::signature::Verifier as _;

    let verifying_key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|e| CryptoError::Verification(format!("invalid P-256 public key: {e}")))?;
    let sig = p256::ecdsa::Signature::from_slice(signature)
        .map_err(|e| CryptoError::Verification(format!("invalid P-256 signature: {e}")))?;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| CryptoError::Verification(format!("signature verification failed: {e}")))
}

/// Verify an ECDSA secp256k1 signature (JWS `alg: ES256K`).
pub fn verify_secp256k1(
    data: &[u8],
    signature: &[u8; 64],
    public_key_sec1: &[u8],
) -> Result<(), CryptoError> {
    use k256::ecdsa::signature::Verifier as _;

    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key_sec1)
        .map_err(|e| CryptoError::Verification(format!("invalid secp256k1 public key: {e}")))?;
    let sig = k256::ecdsa::Signature::from_slice(signature)
        .map_err(|e| CryptoError::Verification(format!("invalid secp256k1 signature: {e}")))?;
    verifying_key
        .verify(data, &sig)
        .map_err(|e| CryptoError::Verification(format!("signature verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The identity point as a public key with the signature `R = identity,
    /// S = 0` satisfies the cofactorless equation for every message, so plain
    /// `verify` accepts it. `verify_strict` refuses the small-order key.
    #[test]
    fn small_order_key_forgery_is_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(&identity);

        let lenient = ed25519_dalek::VerifyingKey::from_bytes(&identity).unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&signature);
        assert!(
            ed25519_dalek::Verifier::verify(&lenient, b"any message", &sig).is_ok(),
            "precondition: the lenient check accepts the forgery"
        );

        let err = verify(b"any message", &signature, &identity).unwrap_err();
        assert!(matches!(err, CryptoError::Verification(_)), "got {err:?}");
    }
}
