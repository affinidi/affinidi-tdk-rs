//! SLH-DSA (FIPS 205) Secret generation for the SHA2-128s parameter set.

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
}
