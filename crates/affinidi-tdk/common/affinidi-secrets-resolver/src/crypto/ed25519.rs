use affinidi_crypto::{JWK, KeyType, OctectParams, Params};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    errors::SecretsResolverError,
    secrets::{Secret, SecretMaterial, SecretType},
};

impl Secret {
    /// Creates a random ed25519 signing key pair
    /// kid: Key ID, if none specified then a random value is assigned
    pub fn generate_ed25519(kid: Option<&str>, seed: Option<&[u8; 32]>) -> Self {
        let keypair = affinidi_crypto::ed25519::generate(seed);

        let kid = kid.map(|k| k.to_string()).unwrap_or_else(|| {
            use rand::{RngCore, rngs::OsRng};
            BASE64_URL_SAFE_NO_PAD.encode(OsRng.next_u64().to_ne_bytes())
        });

        Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(keypair.jwk.clone()),
            private_bytes: keypair.private_bytes,
            public_bytes: keypair.public_bytes,
            key_type: KeyType::Ed25519,
        }
    }

    /// Creates a random x25519 encryption key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// seed: Optional seed the x25519 key is derived from
    pub fn generate_x25519(
        kid: Option<&str>,
        seed: Option<&[u8; 32]>,
    ) -> Result<Self, SecretsResolverError> {
        let seed = if let Some(seed) = seed {
            *seed
        } else {
            affinidi_crypto::ed25519::ed25519_private_to_x25519(
                Secret::generate_ed25519(kid, None)
                    .private_bytes
                    .first_chunk::<32>()
                    .unwrap(),
            )
        };

        let x25519 = StaticSecret::from(seed);
        let x25519_public: PublicKey = PublicKey::from(&x25519);

        Ok(Secret {
            id: kid.unwrap_or("x25519").to_string(),
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::OKP(OctectParams {
                    curve: "X25519".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD.encode(x25519_public.as_bytes()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(x25519.as_bytes())),
                }),
            }),
            private_bytes: x25519.to_bytes().to_vec(),
            public_bytes: x25519_public.to_bytes().to_vec(),
            key_type: KeyType::X25519,
        })
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    use crate::secrets::Secret;

    #[test]
    fn check_x25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("_wYeKm00KWi8H861TsQLVkbAwWOVe0-T9n5Pa80VwTs")
            .unwrap();

        let mut a: [u8; 32] = [0; 32];
        a.copy_from_slice(&bytes[0..32]);

        let x25519 = Secret::generate_x25519(None, Some(&a)).unwrap();

        assert_eq!(
            x25519.get_public_bytes(),
            BASE64_URL_SAFE_NO_PAD
                .decode("ozI6dU2afJs4eyCXxs1FB-rNbn5UgPSHKHRNLRUlLnU")
                .unwrap()
        );
    }

    #[test]
    fn check_ed25519_from_seed() {
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode("X20biMbNG8QUQDnBv4RrZzkS3Civfc2zWHcDkeUeS9g")
            .unwrap();

        let mut a: [u8; 32] = [0; 32];
        a.copy_from_slice(&bytes[0..32]);

        let ed25519 = Secret::generate_ed25519(None, Some(&a));

        assert_eq!(
            ed25519.get_public_bytes(),
            BASE64_URL_SAFE_NO_PAD
                .decode("yb2ttOBWPH2qO-oTrFGs8mgw3cu0nCfjnPt-q9dag7E")
                .unwrap()
        );
    }
}
