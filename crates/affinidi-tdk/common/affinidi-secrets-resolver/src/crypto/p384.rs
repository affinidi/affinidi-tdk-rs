use crate::{
    errors::SecretsResolverError,
    jwk::{ECParams, JWK, Params},
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p384::{
    EncodedPoint,
    ecdsa::{SigningKey, VerifyingKey},
};
use rand::{RngCore, rngs::OsRng};

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
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::EC(ECParams {
                    curve: "P384".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    y: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).y().unwrap()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes())),
                }),
            }),
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::P384,
        })
    }

    /// Generates a Public JWK from a multikey value
    pub fn p384_public_jwk(data: &[u8]) -> Result<JWK, SecretsResolverError> {
        let ep = EncodedPoint::from_bytes(data).map_err(|e| {
            SecretsResolverError::KeyError(format!("P384 public key isn't valid: {e}"))
        })?;

        let params = ECParams {
            curve: "P-384".to_string(),
            d: None,
            x: BASE64_URL_SAFE_NO_PAD.encode(
                ep.x()
                    .ok_or_else(|| {
                        SecretsResolverError::KeyError("Couldn't get X coordinate".to_string())
                    })?
                    .as_slice(),
            ),
            y: BASE64_URL_SAFE_NO_PAD.encode(
                ep.y()
                    .ok_or_else(|| {
                        SecretsResolverError::KeyError("Couldn't get Y coordinate".to_string())
                    })?
                    .as_slice(),
            ),
        };

        Ok(JWK {
            key_id: None,
            params: Params::EC(params),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        jwk::Params,
        secrets::{Secret, SecretMaterial},
    };
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

        if let SecretMaterial::JWK(jwk) = p384_secret.secret_material
            && let Params::EC(params) = jwk.params
        {
            if let Some(params_d) = &params.d {
                assert_eq!(params_d, d);
            } else {
                panic!("No private key material for P384 secret")
            }
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(p384_secret.private_bytes, secret_bytes);
        assert_eq!(p384_secret.public_bytes, public_bytes);
    }
}
