use affinidi_crypto::KeyType;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use rand::{TryRng, rngs::SysRng};

use crate::{
    errors::SecretsResolverError,
    secrets::{Secret, SecretMaterial, SecretType},
};

impl Secret {
    /// Creates a P-521 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_p521(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let keypair = affinidi_crypto::p521::generate(secret)?;

        let kid = kid.map(|k| k.to_string()).unwrap_or_else(|| {
            BASE64_URL_SAFE_NO_PAD.encode(SysRng.try_next_u64().unwrap().to_ne_bytes())
        });

        Ok(Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(keypair.jwk.clone()),
            private_bytes: keypair.private_bytes,
            public_bytes: keypair.public_bytes,
            key_type: KeyType::P521,
        })
    }
}

#[cfg(test)]
mod tests {
    use affinidi_crypto::Params;

    use crate::secrets::{Secret, SecretMaterial};

    #[test]
    fn check_p521_roundtrip() {
        // Generate, reload from the private bytes, and confirm the JWK and raw
        // bytes are stable (proves load + public-key derivation agree).
        let first =
            Secret::generate_p521(Some("did:web:example#p521"), None).expect("generate P-521");
        let reloaded =
            Secret::generate_p521(Some("did:web:example#p521"), Some(&first.private_bytes))
                .expect("reload P-521");

        assert_eq!(reloaded.private_bytes, first.private_bytes);
        assert_eq!(reloaded.public_bytes, first.public_bytes);
        // P-521 raw private scalar is 66 bytes; uncompressed point is 133.
        assert_eq!(first.private_bytes.len(), 66);
        assert_eq!(first.public_bytes.len(), 133);

        if let SecretMaterial::JWK(jwk) = &reloaded.secret_material
            && let Params::EC(params) = &jwk.params
        {
            assert_eq!(params.curve, "P-521");
            assert!(params.d.is_some(), "private key material present");
        } else {
            panic!("expected EC JWK secret material");
        }
    }
}
