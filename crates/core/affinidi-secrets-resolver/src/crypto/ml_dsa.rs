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

/// Assemble a `Secret` with its `secret_material` populated from the seed.
///
/// `secret_material` is the only part of a `Secret` that serde writes —
/// `private_bytes`, `public_bytes` and `key_type` are all `#[serde(skip)]`, and
/// the key type is recovered on the way back in from the multicodec prefix of
/// this very string. Leaving it empty therefore does not produce a `Secret`
/// that persists badly; it produces one that does not persist at all.
///
/// The encoding is infallible for the three ML-DSA parameter sets: each has a
/// registered `-priv-seed` multicodec and the seed is always 32 bytes.
fn ml_dsa_secret(
    kid: Option<&str>,
    key_type: KeyType,
    kp: affinidi_crypto::ml_dsa::KeyPair,
) -> Secret {
    let mut secret = Secret {
        id: kid.map(str::to_string).unwrap_or_else(random_kid),
        type_: SecretType::Multikey,
        secret_material: SecretMaterial::PrivateKeyMultibase(String::new()),
        private_bytes: kp.private_bytes,
        public_bytes: kp.public_bytes,
        key_type,
    };
    let multibase = secret
        .get_private_keymultibase()
        .expect("ML-DSA seeds have a registered private-key multicodec");
    secret.secret_material = SecretMaterial::PrivateKeyMultibase(multibase);
    secret
}

impl Secret {
    /// Creates a random ML-DSA-44 signing key pair.
    /// `kid`: Key ID, if none specified a random value is assigned.
    /// `seed`: Optional 32-byte seed (xi) for deterministic generation.
    pub fn generate_ml_dsa_44(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_44(seed);
        ml_dsa_secret(kid, KeyType::MlDsa44, kp)
    }

    /// Creates a random ML-DSA-65 signing key pair.
    pub fn generate_ml_dsa_65(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_65(seed);
        ml_dsa_secret(kid, KeyType::MlDsa65, kp)
    }

    /// Creates a random ML-DSA-87 signing key pair.
    pub fn generate_ml_dsa_87(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let kp = affinidi_crypto::ml_dsa::generate_ml_dsa_87(seed);
        ml_dsa_secret(kid, KeyType::MlDsa87, kp)
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

    /// A generated ML-DSA secret survives the serde round-trip that every
    /// on-disk secret store performs.
    ///
    /// This is the check the generators previously had no way to pass: they
    /// left `secret_material` empty, so `to_string` wrote
    /// `"privateKeyMultibase": ""` and the read back failed in
    /// `Secret::from_multibase`. The seed was not corrupted — it was simply
    /// never written, and the loss only showed up on the next process start.
    #[test]
    fn ml_dsa_secret_survives_a_serde_round_trip() {
        for (label, original) in [
            (
                "44",
                Secret::generate_ml_dsa_44(Some("k1"), Some(&[7u8; 32])),
            ),
            (
                "65",
                Secret::generate_ml_dsa_65(Some("k2"), Some(&[8u8; 32])),
            ),
            (
                "87",
                Secret::generate_ml_dsa_87(Some("k3"), Some(&[9u8; 32])),
            ),
        ] {
            let json = serde_json::to_string(&original)
                .unwrap_or_else(|e| panic!("ML-DSA-{label} failed to serialise: {e}"));

            // The private half must actually be in the JSON.
            assert!(
                !json.contains(r#""privateKeyMultibase":"""#),
                "ML-DSA-{label} serialised an empty private key: {json}"
            );

            let restored: Secret = serde_json::from_str(&json)
                .unwrap_or_else(|e| panic!("ML-DSA-{label} failed to deserialise: {e}"));

            assert_eq!(restored.id, original.id, "ML-DSA-{label} kid");
            assert_eq!(
                restored.private_bytes, original.private_bytes,
                "ML-DSA-{label} seed"
            );
            // The key type is carried only by the multicodec prefix of the
            // private-key string, so this asserts the prefix survived too.
            assert_eq!(
                restored.key_type, original.key_type,
                "ML-DSA-{label} key type"
            );
            assert_eq!(
                restored.public_bytes, original.public_bytes,
                "ML-DSA-{label} public key re-derived from the seed"
            );
        }
    }
}
