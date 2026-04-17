//! Ed25519 signing and verification for TSP outer signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::error::TspError;

/// Sign data with an Ed25519 private key.
///
/// Returns a 64-byte Ed25519 signature.
pub fn sign(data: &[u8], private_key: &[u8; 32]) -> Result<[u8; 64], TspError> {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
pub fn verify(data: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> Result<(), TspError> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| TspError::Verification(format!("invalid public key: {e}")))?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(data, &sig)
        .map_err(|e| TspError::Verification(format!("signature verification failed: {e}")))
}

/// Derive the Ed25519 public key from a private key.
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();
        let data = b"test message for TSP signing";

        let sig = sign(data, &sk.to_bytes()).unwrap();
        verify(data, &sig, &pk).unwrap();
    }

    #[test]
    fn wrong_key_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let wrong_pk = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
        let data = b"test";

        let sig = sign(data, &sk.to_bytes()).unwrap();
        assert!(verify(data, &sig, &wrong_pk).is_err());
    }

    #[test]
    fn tampered_data_fails() {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        let sig = sign(b"original", &sk.to_bytes()).unwrap();
        assert!(verify(b"tampered", &sig, &pk).is_err());
    }

    #[test]
    fn public_key_derivation() {
        let sk = SigningKey::generate(&mut OsRng);
        let expected_pk = sk.verifying_key().to_bytes();
        let derived_pk = public_key_from_private(&sk.to_bytes());
        assert_eq!(expected_pk, derived_pk);
    }
}
