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

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

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

    /// NIST ACVP SLH-DSA-keyGen-FIPS205 tcId=1 (SLH-DSA-SHA2-128s).
    ///
    /// Source: <https://github.com/usnistgov/ACVP-Server>
    /// `gen-val/json-files/SLH-DSA-keyGen-FIPS205/{prompt,expectedResults}.json`.
    /// Catches param-set dispatch and encoding regressions against the
    /// authoritative FIPS 205 reference.
    #[test]
    fn slh_dsa_sha2_128s_nist_kat_keygen() {
        let sk_seed = hex("173D04C938C1C36BF289C3C022D04B14");
        let sk_prf = hex("63AE23C41AA546DA589774AC20B745C4");
        let pk_seed = hex("0D794777914C99766827F0F09CA972BE");
        let expected_pk = hex("0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C");

        let sk = SigningKey::<Sha2_128s>::slh_keygen_internal(&sk_seed, &sk_prf, &pk_seed);
        let pk_bytes = sk.as_ref().to_bytes();
        assert_eq!(pk_bytes.as_slice(), expected_pk.as_slice());

        // And sanity-check: signing then verifying roundtrips under these NIST keys.
        let sk_bytes = sk.to_bytes();
        let sig = sign_slh_dsa_sha2_128s(sk_bytes.as_slice(), b"acvp-roundtrip").unwrap();
        verify_slh_dsa_sha2_128s(pk_bytes.as_slice(), b"acvp-roundtrip", &sig).unwrap();
    }
}
