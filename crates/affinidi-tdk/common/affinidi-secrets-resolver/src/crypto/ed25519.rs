use crate::secrets::{KeyType, Secret, SecretMaterial, SecretType};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde_json::json;

impl Secret {
    /// Creates a random ed25519 signing key pair
    /// kid: Key ID, if none specified then a random value is assigned
    pub fn generate_ed25519(kid: Option<&str>) -> Self {
        let mut csprng = OsRng;

        let signing_key: SigningKey = SigningKey::generate(&mut csprng);

        let kid = if let Some(kid) = kid {
            kid.to_string()
        } else {
            BASE64_URL_SAFE_NO_PAD.encode(csprng.next_u64().to_ne_bytes())
        };

        Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "crv": "Ed25519",
                    "d": BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
                    "kty": "EC",
                    "x": BASE64_URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
                }),
            },
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: signing_key.verifying_key().to_bytes().to_vec(),
            key_type: KeyType::Ed25519,
        }
    }
}
