use crate::{
    errors::SecretsResolverError,
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde_json::json;

impl Secret {
    /// Creates a p256 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_p256(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let mut csprng = OsRng;

        let signing_key = if let Some(secret) = secret {
            SigningKey::from_slice(secret).map_err(|e| {
                SecretsResolverError::KeyError(format!("P256 secret material isn't valid: {e}"))
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
                    "crv": "P256",
                    "d": BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
                    "kty": "EC",
                    "x": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    "y": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
                }),
            },
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::P256,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::secrets::{Secret, SecretMaterial};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    #[test]
    fn check_p256_encoding() {
        let d = "0Dn-Cq97w8lVf0Fe6pQaynM8obOYaouDpRHUQlN9mXw";
        let x = "OqtR8tur0bXp3dpvHg8S4R_bjFEFGBfv4WKYU6o7llc";
        let y = "nPBTM3K9oYq4YyajBb7BTKCOZBWJIqvX0Cbokd03QK8";
        let secret_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(d)
            .expect("Couldn't decode secret bytes");

        let mut public_bytes: Vec<u8> = vec![4]; // Leading byte '4' denotes uncompressed
        // public_bytes
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(x).expect("Couldn't decode X"));
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(y).expect("Couldn't decode Y"));

        let p256_secret =
            Secret::generate_p256(None, Some(&secret_bytes)).expect("Couldbn't create P256 secret");

        if let SecretMaterial::JWK {
            private_key_jwk: jwk,
        } = p256_secret.secret_material
        {
            assert_eq!(jwk.get("d").unwrap().as_str().unwrap(), d);
            assert_eq!(jwk.get("x").unwrap().as_str().unwrap(), x);
            assert_eq!(jwk.get("y").unwrap().as_str().unwrap(), y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(p256_secret.private_bytes, secret_bytes);
        assert_eq!(p256_secret.public_bytes, public_bytes);
    }
}
