//! ML-DSA (FIPS 204) Secret generation.
//!
//! Private material is stored as the 32-byte seed `xi`. Public material is
//! the FIPS 204 encoded verifying key. No JWK representation is defined by
//! W3C `di-quantum-safe`, so `SecretMaterial::JWK` is not produced for these
//! keys — callers should use `from_multibase` / `get_*_keymultibase` instead.

use affinidi_crypto::KeyType;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{TryRng, rngs::SysRng};

use crate::secrets::{Secret, SecretMaterial, SecretType};

fn random_kid() -> String {
    BASE64_URL_SAFE_NO_PAD.encode(SysRng.try_next_u64().unwrap().to_ne_bytes())
}

impl Secret {
    /// Creates a random ML-DSA-44 signing key pair.
    /// `kid`: Key ID, if none specified a random value is assigned.
    /// `seed`: Optional 32-byte seed (xi) for deterministic generation.
    pub fn generate_ml_dsa_44(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_44(seed);
        Secret {
            id: kid.map(str::to_string).unwrap_or_else(random_kid),
            type_: SecretType::Multikey,
            secret_material: SecretMaterial::PrivateKeyMultibase(String::new()),
            private_bytes: kp.private_bytes,
            public_bytes: kp.public_bytes,
            key_type: KeyType::MlDsa44,
        }
    }

    /// Creates a random ML-DSA-65 signing key pair.
    pub fn generate_ml_dsa_65(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_65(seed);
        Secret {
            id: kid.map(str::to_string).unwrap_or_else(random_kid),
            type_: SecretType::Multikey,
            secret_material: SecretMaterial::PrivateKeyMultibase(String::new()),
            private_bytes: kp.private_bytes,
            public_bytes: kp.public_bytes,
            key_type: KeyType::MlDsa65,
        }
    }

    /// Creates a random ML-DSA-87 signing key pair.
    pub fn generate_ml_dsa_87(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_87(seed);
        Secret {
            id: kid.map(str::to_string).unwrap_or_else(random_kid),
            type_: SecretType::Multikey,
            secret_material: SecretMaterial::PrivateKeyMultibase(String::new()),
            private_bytes: kp.private_bytes,
            public_bytes: kp.public_bytes,
            key_type: KeyType::MlDsa87,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ml_dsa_44_deterministic() {
        let a = Secret::generate_ml_dsa_44(Some("k1"), Some(&[1u8; 32]));
        let b = Secret::generate_ml_dsa_44(Some("k1"), Some(&[1u8; 32]));
        assert_eq!(a.public_bytes, b.public_bytes);
        assert_eq!(a.private_bytes.len(), 32);
        assert_eq!(a.public_bytes.len(), 1312);
    }
}
