//! SLH-DSA (FIPS 205) key operations for the SHA2-128s parameter set.
//!
//! Private and public keys are stored as their FIPS 205 raw encodings
//! (64 and 32 bytes respectively for SHA2-128s).

use slh_dsa::signature::{Signer, Verifier};
use slh_dsa::{Sha2_128s, Signature, SigningKey, VerifyingKey};

use crate::{CryptoError, KeyType, error::Result};

/// Generated SLH-DSA-SHA2-128s key pair.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
}

/// Generates an SLH-DSA-SHA2-128s key pair.
pub fn generate_slh_dsa_sha2_128s() -> KeyPair {
    let mut rng = rand_10::rng();
    let sk = SigningKey::<Sha2_128s>::new(&mut rng);
    let vk = sk.as_ref();
    KeyPair {
        key_type: KeyType::SlhDsaSha2_128s,
        private_bytes: sk.to_bytes().to_vec(),
        public_bytes: vk.to_bytes().to_vec(),
    }
}

/// Reconstructs an SLH-DSA-SHA2-128s key pair from a raw 64-byte private key.
pub fn key_pair_from_private_sha2_128s(private_key: &[u8]) -> Result<KeyPair> {
    let sk = SigningKey::<Sha2_128s>::try_from(private_key)
        .map_err(|e| CryptoError::KeyError(format!("Invalid SLH-DSA private key: {e}")))?;
    let vk = sk.as_ref();
    Ok(KeyPair {
        key_type: KeyType::SlhDsaSha2_128s,
        private_bytes: sk.to_bytes().to_vec(),
        public_bytes: vk.to_bytes().to_vec(),
    })
}

/// Signs `data` with SLH-DSA-SHA2-128s given a raw private key.
pub fn sign_slh_dsa_sha2_128s(private_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let sk = SigningKey::<Sha2_128s>::try_from(private_key)
        .map_err(|e| CryptoError::KeyError(format!("Invalid SLH-DSA private key: {e}")))?;
    let sig = sk.sign(data);
    Ok(sig.to_bytes().to_vec())
}

/// Verifies an SLH-DSA-SHA2-128s signature.
pub fn verify_slh_dsa_sha2_128s(public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let vk = VerifyingKey::<Sha2_128s>::try_from(public_key)
        .map_err(|e| CryptoError::KeyError(format!("Invalid SLH-DSA public key: {e}")))?;
    let sig = Signature::<Sha2_128s>::try_from(signature)
        .map_err(|e| CryptoError::KeyError(format!("Invalid SLH-DSA signature: {e}")))?;
    vk.verify(data, &sig)
        .map_err(|e| CryptoError::KeyError(format!("SLH-DSA verification failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slh_dsa_sha2_128s_roundtrip() {
        let kp = generate_slh_dsa_sha2_128s();
        assert_eq!(kp.private_bytes.len(), 64);
        assert_eq!(kp.public_bytes.len(), 32);

        let msg = b"hello slh";
        let sig = sign_slh_dsa_sha2_128s(&kp.private_bytes, msg).unwrap();
        assert_eq!(sig.len(), 7856);
        verify_slh_dsa_sha2_128s(&kp.public_bytes, msg, &sig).unwrap();
    }

    #[test]
    fn slh_dsa_tampered_sig_fails() {
        let kp = generate_slh_dsa_sha2_128s();
        let mut sig = sign_slh_dsa_sha2_128s(&kp.private_bytes, b"x").unwrap();
        sig[42] ^= 0x01;
        assert!(verify_slh_dsa_sha2_128s(&kp.public_bytes, b"x", &sig).is_err());
    }
}
