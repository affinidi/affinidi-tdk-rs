//! secp256k1 key operations

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use k256::{
    AffinePoint, EncodedPoint,
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand::rngs::OsRng;

use crate::{CryptoError, ECParams, JWK, KeyType, Params, error::Result};

/// Generated key pair with raw bytes and JWK representation
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
    pub jwk: JWK,
}

/// Generates a secp256k1 key pair
pub fn generate(secret: Option<&[u8]>) -> Result<KeyPair> {
    let signing_key = match secret {
        Some(secret) => SigningKey::from_slice(secret).map_err(|e| {
            CryptoError::KeyError(format!("secp256k1 secret material isn't valid: {e}"))
        })?,
        None => SigningKey::random(&mut OsRng),
    };

    let verifying_key = VerifyingKey::from(&signing_key);
    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).to_bytes().to_vec();

    Ok(KeyPair {
        key_type: KeyType::Secp256k1,
        private_bytes: private_bytes.clone(),
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::EC(ECParams {
                curve: "secp256k1".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
                y: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    })
}

/// Generates a public JWK from secp256k1 raw bytes (compressed or uncompressed)
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    let ep = EncodedPoint::from_bytes(data)
        .map_err(|e| CryptoError::KeyError(format!("secp256k1 public key isn't valid: {e}")))?;

    // Convert to AffinePoint to validate the point is on the curve
    let ap: AffinePoint = AffinePoint::from_encoded_point(&ep)
        .into_option()
        .ok_or_else(|| {
            CryptoError::KeyError("Couldn't convert secp256k1 EncodedPoint to AffinePoint".into())
        })?;

    // Decompress to get x and y coordinates
    let ep = ap.to_encoded_point(false);

    Ok(JWK {
        key_id: None,
        params: Params::EC(ECParams {
            curve: "secp256k1".to_string(),
            x: BASE64_URL_SAFE_NO_PAD.encode(
                ep.x()
                    .ok_or_else(|| CryptoError::KeyError("Couldn't get X coordinate".into()))?
                    .as_slice(),
            ),
            y: BASE64_URL_SAFE_NO_PAD.encode(
                ep.y()
                    .ok_or_else(|| CryptoError::KeyError("Couldn't get Y coordinate".into()))?
                    .as_slice(),
            ),
            d: None,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_from_secret() {
        let d = "mD9ssK9cdYw7hW9cT6rSSi67urjBz-7fce3Q6bAka-E";
        let x = "S_caroUAnHCypb9QTfWkCpB2Yx792O3uw_6eDNbGQLo";
        let y = "k-FA2c2UBoH4D_PWZ7LPiRDr5WPbahMi8duNOU1Lcdc";

        let secret_bytes = BASE64_URL_SAFE_NO_PAD.decode(d).unwrap();
        let keypair = generate(Some(&secret_bytes)).unwrap();

        if let Params::EC(params) = &keypair.jwk.params {
            assert_eq!(params.d.as_ref().unwrap(), d);
            assert_eq!(params.x, x);
            assert_eq!(params.y, y);
        } else {
            panic!("Expected EC params");
        }
    }

    #[test]
    fn public_jwk_from_compressed() {
        let bytes: [u8; 33] = [
            2, 83, 143, 208, 17, 61, 39, 58, 251, 55, 174, 187, 147, 60, 3, 197, 119, 164, 52, 196,
            220, 107, 174, 114, 244, 201, 214, 48, 217, 125, 54, 168, 92,
        ];

        let jwk = public_jwk(&bytes).unwrap();

        if let Params::EC(params) = &jwk.params {
            assert_eq!(params.curve, "secp256k1");
            assert!(params.d.is_none());
            assert_eq!(params.x, "U4_QET0nOvs3rruTPAPFd6Q0xNxrrnL0ydYw2X02qFw");
            assert_eq!(params.y, "H2xAfO9HZXYAdMdDckRv0Hl73YsE5PpAh9w2z4ShKBA");
        } else {
            panic!("Expected EC params");
        }
    }
}
