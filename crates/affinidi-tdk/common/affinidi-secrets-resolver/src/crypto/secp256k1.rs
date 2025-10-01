use crate::{
    errors::SecretsResolverError,
    jwk::{ECParams, JWK, Params},
    secrets::{KeyType, Secret, SecretMaterial, SecretType},
};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use k256::{
    AffinePoint, EncodedPoint,
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::{RngCore, rngs::OsRng};

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
            secret_material: SecretMaterial::JWK(JWK {
                key_id: None,
                params: Params::EC(ECParams {
                    curve: "secp256k1".to_string(),
                    x: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).x().unwrap()),
                    y: BASE64_URL_SAFE_NO_PAD
                        .encode(verifying_key.to_encoded_point(false).y().unwrap()),
                    d: Some(BASE64_URL_SAFE_NO_PAD.encode(signing_key.to_bytes())),
                }),
            }),
            private_bytes: signing_key.to_bytes().to_vec(),
            public_bytes: verifying_key.to_encoded_point(false).to_bytes().to_vec(),
            key_type: KeyType::Secp256k1,
        })
    }

    /// Generates a Public JWK from a multikey value
    pub fn secp256k1_public_jwk(data: &[u8]) -> Result<JWK, SecretsResolverError> {
        let ep = EncodedPoint::from_bytes(data).map_err(|e| {
            SecretsResolverError::KeyError(format!("secp256k1 public key isn't valid: {e}"))
        })?;

        // Convert to AffinePoint to validate the point is on the curve
        let ap: AffinePoint = if let Some(ap) = AffinePoint::from_encoded_point(&ep).into() {
            ap
        } else {
            return Err(SecretsResolverError::KeyError(
                "Couldn't convert secp256k1 EncodedPoint to AffinePoint".to_string(),
            ));
        };

        // Decompress the AffinePoint back to EncodedPoint to get x and y coordinates
        let ep = ap.to_encoded_point(false);

        let params = ECParams {
            curve: "secp256k1".to_string(),
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

        if let SecretMaterial::JWK(jwk) = secp256k1_secret.secret_material
            && let Params::EC(params) = jwk.params
        {
            if let Some(params_d) = &params.d {
                assert_eq!(params_d, d);
            } else {
                panic!("No private key material for secp256k1 secret")
            }
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("No secret JWK");
        }

        assert_eq!(secp256k1_secret.private_bytes, secret_bytes);
        assert_eq!(secp256k1_secret.public_bytes, public_bytes);
    }

    #[test]
    fn check_public_jwk() {
        let bytes: [u8; 33] = [
            2, 83, 143, 208, 17, 61, 39, 58, 251, 55, 174, 187, 147, 60, 3, 197, 119, 164, 52, 196,
            220, 107, 174, 114, 244, 201, 214, 48, 217, 125, 54, 168, 92,
        ];
        let a = Secret::secp256k1_public_jwk(&bytes);

        assert!(a.is_ok());

        let a = a.unwrap();
        if let Params::EC(params) = a.params {
            assert_eq!(params.curve, "secp256k1");
            assert!(params.d.is_none(),);
            assert_eq!(params.x, "U4_QET0nOvs3rruTPAPFd6Q0xNxrrnL0ydYw2X02qFw");
            assert_eq!(params.y, "H2xAfO9HZXYAdMdDckRv0Hl73YsE5PpAh9w2z4ShKBA");
        } else {
            panic!("Expected EC Params");
        }
    }
}
