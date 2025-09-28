use crate::{
    errors::SecretsResolverError,
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use k256::ecdsa::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde_json::json;

impl Secret {
    /// Creates a secp256k1 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_secp256k1(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let mut csprng = OsRng;

        let signing_key = if let Some(secret) = secret {
            SigningKey::from_slice(secret).map_err(|e| {
                SecretsResolverError::KeyError(format!(
                    "Secp256k1 secret material isn't valid: {e}"
                ))
            })?
        } else {
            SigningKey::random(&mut csprng)
        };
        let verifying_key = VerifyingKey::from(&signing_key);

        let kid = if let Some(kid) = kid {
            kid.to_string()
        } else {
            BASE64_URL_SAFE_NO_PAD.encode(csprng.next_u64().to_ne_bytes())
        };

        Ok(Secret {
            id: kid,
            type_: SecretType::JsonWebKey2020,
            secret_material: SecretMaterial::JWK {
                private_key_jwk: json!({
                    "crv": "secp256k1",
                    "d": BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
                    "kty": "EC",
                    "x": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    "y": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
                }),
            },
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::Secp256k1,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::secrets::{Secret, SecretMaterial};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    #[test]
    fn check_secp256k1_encoding() {
        let d = "mD9ssK9cdYw7hW9cT6rSSi67urjBz-7fce3Q6bAka-E";
        let x = "S_caroUAnHCypb9QTfWkCpB2Yx792O3uw_6eDNbGQLo";
        let y = "k-FA2c2UBoH4D_PWZ7LPiRDr5WPbahMi8duNOU1Lcdc";
        let secret_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(d)
            .expect("Couldn't decode secret bytes");

        let mut public_bytes: Vec<u8> = vec![4]; // Leading byte '4' denotes uncompressed
        // public_bytes
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(x).expect("Couldn't decode X"));
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(y).expect("Couldn't decode Y"));

        let secp256k1_secret = Secret::generate_secp256k1(None, Some(&secret_bytes))
            .expect("Couldbn't create secp256k1 secret");

        if let SecretMaterial::JWK {
            private_key_jwk: jwk,
        } = secp256k1_secret.secret_material
        {
            assert_eq!(jwk.get("d").unwrap().as_str().unwrap(), d);
            assert_eq!(jwk.get("x").unwrap().as_str().unwrap(), x);
            assert_eq!(jwk.get("y").unwrap().as_str().unwrap(), y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(secp256k1_secret.private_bytes, secret_bytes);
        assert_eq!(secp256k1_secret.public_bytes, public_bytes);
    }
}
