use crate::{
    errors::SecretsResolverError,
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p384::ecdsa::{SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde_json::json;

impl Secret {
    /// Creates a p384 key pair
    /// kid: Key ID, if none specified then a random value is assigned
    /// secret: Generate from secret bytes if known, otherwise random key is generated
    pub fn generate_p384(
        kid: Option<&str>,
        secret: Option<&[u8]>,
    ) -> Result<Self, SecretsResolverError> {
        let mut csprng = OsRng;

        let signing_key = if let Some(secret) = secret {
            SigningKey::from_slice(secret).map_err(|e| {
                SecretsResolverError::KeyError(format!("P384 secret material isn't valid: {e}"))
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
                    "crv": "P384",
                    "d": BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
                    "kty": "EC",
                    "x": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    "y": BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
                }),
            },
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::P384,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::secrets::{Secret, SecretMaterial};
    use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};

    #[test]
    fn check_p384_encoding() {
        let d = "sbb1acpuGPO2P3-aAchoUO5Ghs9Iyecm52HgcvVWR58Pmd-uvKZd-38OhCNCiaNd";
        let x = "zBTXJl2R0sjxCYxvq6_eQovQWTyZUlv5wMWV857GNvYT39h7AMCPCVRrH9l6qVfb";
        let y = "meSAqJ1ycBRzuA2FwKjHWDT6BaDufqxADi6GMSqbCTvZzb0qxgHKdXCXHcbl1EPv";

        let secret_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(d)
            .expect("Couldn't decode secret bytes");

        let mut public_bytes: Vec<u8> = vec![4]; // Leading byte '4' denotes uncompressed
        // public_bytes
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(x).expect("Couldn't decode X"));
        public_bytes.append(&mut BASE64_URL_SAFE_NO_PAD.decode(y).expect("Couldn't decode Y"));

        let p384_secret =
            Secret::generate_p384(None, Some(&secret_bytes)).expect("Couldbn't create P384 secret");

        if let SecretMaterial::JWK {
            private_key_jwk: jwk,
        } = p384_secret.secret_material
        {
            assert_eq!(jwk.get("d").unwrap().as_str().unwrap(), d);
            assert_eq!(jwk.get("x").unwrap().as_str().unwrap(), x);
            assert_eq!(jwk.get("y").unwrap().as_str().unwrap(), y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(p384_secret.private_bytes, secret_bytes);
        assert_eq!(p384_secret.public_bytes, public_bytes);
    }
}
