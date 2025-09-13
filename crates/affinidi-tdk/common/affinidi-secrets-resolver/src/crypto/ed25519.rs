use crate::secrets::{KeyType, Secret, SecretMaterial, SecretType};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use rand::{RngCore, rngs::OsRng};
use serde_json::json;
use sha2::{Digest, Sha512};

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

/// Converts an ed25519 secret to a x25519 secret
pub(crate) fn to_x25519(secret: &Vec<u8>) -> [u8; 32] {
    let mut bytes = Sha512::digest(secret);

    bytes[0] &= 0xF8;
    bytes[31] |= 0x80;
    bytes[31] &= 0x7F;

    let mut a: [u8; 32] = [0; 32]; // Initialize withg zeros

    a.copy_from_slice(&bytes[0..32]);
    a
}

#[cfg(test)]
mod tests {
    use crate::crypto::ed25519::to_x25519;

    const ED25519_SK: [u8; 32] = [
        202, 104, 239, 81, 53, 110, 80, 252, 198, 23, 155, 162, 215, 98, 223, 173, 227, 188, 110,
        54, 127, 45, 185, 206, 174, 29, 44, 147, 76, 66, 196, 195,
    ];
    const CURVE25519_SK: [u8; 32] = [
        200, 255, 64, 61, 17, 52, 112, 33, 205, 71, 186, 13, 131, 12, 241, 136, 223, 5, 152, 40,
        95, 187, 83, 168, 142, 10, 234, 215, 70, 210, 148, 104,
    ];

    #[test]
    fn check_ed25519_to_x25519_key_conversion() {
        assert_eq!(to_x25519(&ED25519_SK.to_vec()), CURVE25519_SK);
    }
}
