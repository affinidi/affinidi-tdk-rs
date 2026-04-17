//! Ed25519 signing and verification (EdDSA).

use ed25519_dalek::{Signer, Verifier};

use crate::error::DIDCommError;

/// Sign data with an Ed25519 private key.
pub fn sign(data: &[u8], private_key: &[u8; 32]) -> Result<[u8; 64], DIDCommError> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes())
}

/// Verify an Ed25519 signature.
pub fn verify(
    data: &[u8],
    signature: &[u8; 64],
    public_key: &[u8; 32],
) -> Result<(), DIDCommError> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|e| DIDCommError::Verification(format!("invalid public key: {e}")))?;
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify(data, &sig)
        .map_err(|e| DIDCommError::Verification(format!("signature verification failed: {e}")))
}

/// Derive the Ed25519 public key from a private key.
pub fn public_key_from_private(private_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);
    signing_key.verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        let data = b"hello DIDComm";
        let sig = sign(data, &sk.to_bytes()).unwrap();
        verify(data, &sig, &pk).unwrap();
    }

    #[test]
    fn wrong_key_fails() {
        let sk1 = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let sk2 = ed25519_dalek::SigningKey::generate(&mut OsRng);

        let sig = sign(b"test", &sk1.to_bytes()).unwrap();
        assert!(verify(b"test", &sig, &sk2.verifying_key().to_bytes()).is_err());
    }
}
