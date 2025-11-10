use crate::{
    errors::SecretsResolverError,
    jwk::{ECParams, JWK, Params},
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use generic_array::GenericArray;
use p256::{
    AffinePoint, EncodedPoint,
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::{RngCore, rngs::OsRng};

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
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::EC(ECParams {
                    curve: "P-256".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    y: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).y().unwrap()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes())),
                }),
            }),
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::P256,
        })
    }

    /// Generates a Public JWK from a multikey value
    pub fn p256_public_jwk(data: &[u8]) -> Result<JWK, SecretsResolverError> {
        let ep = EncodedPoint::from_bytes(data).map_err(|e| {
            SecretsResolverError::KeyError(format!("P-256 public key isn't valid: {e}"))
        })?;

        // Convert to AffinePoint to validate the point is on the curve
        let ap: AffinePoint = if let Some(ap) = AffinePoint::from_encoded_point(&ep).into() {
            ap
        } else {
            return Err(SecretsResolverError::KeyError(
                "Couldn't convert P-256 EncodedPoint to AffinePoint".to_string(),
            ));
        };

        // Decompress the AffinePoint back to EncodedPoint to get x and y coordinates
        let ep = ap.to_encoded_point(false);

        let params = ECParams {
            curve: "P-256".to_string(),
            d: None,
            x: BASE64_URL_SAFE_NO_PAD.encode(
                GenericArray::from_0_14(
                    ep.x()
                        .ok_or_else(|| {
                            SecretsResolverError::KeyError("Couldn't get X coordinate".to_string())
                        })?
                        .to_owned(),
                )
                .as_slice(),
            ),
            y: BASE64_URL_SAFE_NO_PAD.encode(
                GenericArray::from_0_14(
                    ep.y()
                        .ok_or_else(|| {
                            SecretsResolverError::KeyError("Couldn't get Y coordinate".to_string())
                        })?
                        .to_owned(),
                )
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
        jwk::{JWK, Params},
        secrets::{Secret, SecretMaterial},
    };
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

        if let SecretMaterial::JWK(jwk) = &p256_secret.secret_material
            && let Params::EC(params) = &jwk.params
        {
            if let Some(params_d) = &params.d {
                assert_eq!(params_d, d);
            } else {
                panic!("No private key material for P256 secret")
            }
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(p256_secret.private_bytes, secret_bytes);
        assert_eq!(p256_secret.public_bytes, public_bytes);
    }

    #[test]
    fn check_public_jwk() {
        let bytes: [u8; 33] = [
            3, 127, 35, 88, 48, 221, 61, 239, 167, 34, 239, 26, 162, 73, 214, 160, 221, 187, 164,
            249, 144, 176, 129, 117, 56, 147, 63, 87, 54, 64, 101, 53, 66,
        ];
        let a = Secret::p256_public_jwk(&bytes);

        assert!(a.is_ok());

        let a = a.unwrap();
        if let Params::EC(params) = &a.params {
            assert_eq!(params.curve, "P-256");
            assert!(params.d.is_none(),);
            assert_eq!(params.x, "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI");
            assert_eq!(params.y, "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU");
        } else {
            panic!("Expected EC Params");
        }
    }

    #[test]
    fn check_p256_public_multi_encoded() {
        assert!(JWK::from_multikey("zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169").is_ok());
        assert!(JWK::from_multikey("zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv").is_ok());
    }
}
