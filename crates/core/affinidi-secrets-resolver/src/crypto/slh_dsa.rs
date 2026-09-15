//! SLH-DSA (FIPS 205) Secret generation for the SHA2-128s parameter set.
//!
//! **These secrets are memory-only.** SLH-DSA has no registered private-key
//! multicodec, and a `Secret`'s key type is carried nowhere but the multicodec
//! prefix of its private-key string — so there is no way to write one down that
//! can be read back as SLH-DSA. Unlike ML-DSA, whose 32-byte seed has codecs
//! `0x131a`–`0x131c`, this cannot be fixed here: it needs a codec registered
//! upstream, or a `SecretMaterial` variant that carries the algorithm
//! alongside raw bytes. Until then `secret_material` is left empty deliberately,
//! and `slh_dsa_secret_does_not_survive_a_serde_round_trip` pins that so it is
//! not mistaken for the ML-DSA defect it resembles.

use affinidi_crypto::KeyType;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{TryRng, rngs::SysRng};

use crate::secrets::{Secret, SecretMaterial, SecretType};

fn random_kid() -> String {
    BASE64_URL_SAFE_NO_PAD.encode(SysRng.try_next_u64().unwrap().to_ne_bytes())
}

impl Secret {
    /// Creates a random SLH-DSA-SHA2-128s signing key pair.
    pub fn generate_slh_dsa_sha2_128s(kid: Option<&str>) -> Self {
        let kp = affinidi_crypto::slh_dsa::generate_slh_dsa_sha2_128s();
        Secret {
            id: kid.map(str::to_string).unwrap_or_else(random_kid),
            type_: SecretType::Multikey,
            secret_material: SecretMaterial::PrivateKeyMultibase(String::new()),
            private_bytes: kp.private_bytes,
            public_bytes: kp.public_bytes,
            key_type: KeyType::SlhDsaSha2_128s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_slh_dsa_128s_sizes() {
        let s = Secret::generate_slh_dsa_sha2_128s(Some("k1"));
        assert_eq!(s.private_bytes.len(), 64);
        assert_eq!(s.public_bytes.len(), 32);
    }

    /// SLH-DSA secrets are memory-only, and this pins it.
    ///
    /// The ML-DSA generators had the same empty `secret_material` and it was a
    /// defect; here it is the only honest option, because no private-key
    /// multicodec exists to write. The distinction matters: someone fixing the
    /// ML-DSA bug should not "fix" this one by inventing a code point.
    ///
    /// Change this test when a codec is registered — not before.
    #[test]
    fn slh_dsa_secret_does_not_survive_a_serde_round_trip() {
        let original = Secret::generate_slh_dsa_sha2_128s(Some("k1"));

        assert!(
            original.get_private_keymultibase().is_err(),
            "a private-key multicodec appeared for SLH-DSA; if it is registered \
             upstream, populate secret_material in the generator and make this \
             a round-trip test like the ML-DSA one"
        );

        let json = serde_json::to_string(&original).expect("serialises");
        assert!(
            json.contains(r#""privateKeyMultibase":"""#),
            "expected an empty private key, got: {json}"
        );
        assert!(
            serde_json::from_str::<Secret>(&json).is_err(),
            "an SLH-DSA secret deserialised; the key type cannot be recovered \
             without a multicodec, so this would be a silently wrong key"
        );
    }
}
