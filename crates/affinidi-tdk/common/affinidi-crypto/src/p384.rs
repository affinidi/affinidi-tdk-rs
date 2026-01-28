//! P-384 (secp384r1) key operations

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p384::{
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

/// Generates a P-384 key pair
pub fn generate(secret: Option<&[u8]>) -> Result<KeyPair> {
    let signing_key = match secret {
        Some(secret) => SigningKey::from_slice(secret)
            .map_err(|e| CryptoError::KeyError(format!("P-384 secret material isn't valid: {e}")))?,
        None => SigningKey::random(&mut OsRng),
    };

    let verifying_key = VerifyingKey::from(&signing_key);
    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).to_bytes().to_vec();

    Ok(KeyPair {
        key_type: KeyType::P384,
        private_bytes: private_bytes.clone(),
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::EC(ECParams {
                curve: "P-384".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).x().unwrap()),
                y: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_encoded_point(false).y().unwrap()),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    })
}

/// Generates a public JWK from P-384 raw bytes (compressed or uncompressed)
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    let ep = EncodedPoint::from_bytes(data)
        .map_err(|e| CryptoError::KeyError(format!("P-384 public key isn't valid: {e}")))?;

    // Convert to AffinePoint to validate the point is on the curve
    let ap: AffinePoint = AffinePoint::from_encoded_point(&ep)
        .into_option()
        .ok_or_else(|| {
            CryptoError::KeyError("Couldn't convert P-384 EncodedPoint to AffinePoint".into())
        })?;

    // Decompress to get x and y coordinates
    let ep = ap.to_encoded_point(false);

    Ok(JWK {
        key_id: None,
        params: Params::EC(ECParams {
            curve: "P-384".to_string(),
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
        let d = "sbb1acpuGPO2P3-aAchoUO5Ghs9Iyecm52HgcvVWR58Pmd-uvKZd-38OhCNCiaNd";
        let x = "zBTXJl2R0sjxCYxvq6_eQovQWTyZUlv5wMWV857GNvYT39h7AMCPCVRrH9l6qVfb";
        let y = "meSAqJ1ycBRzuA2FwKjHWDT6BaDufqxADi6GMSqbCTvZzb0qxgHKdXCXHcbl1EPv";

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
        let bytes: [u8; 49] = [
            3, 148, 137, 211, 198, 95, 31, 140, 178, 169, 253, 64, 171, 196, 141, 22, 14, 73, 90,
            134, 47, 187, 251, 254, 137, 110, 216, 135, 142, 36, 111, 50, 248, 94, 118, 18, 149,
            116, 112, 95, 139, 97, 194, 99, 203, 127, 64, 156, 156,
        ];

        let jwk = public_jwk(&bytes).unwrap();

        if let Params::EC(params) = &jwk.params {
            assert_eq!(params.curve, "P-384");
            assert!(params.d.is_none());
            assert_eq!(
                params.x,
                "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc"
            );
            assert_eq!(
                params.y,
                "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv"
            );
        } else {
            panic!("Expected EC params");
        }
    }
}
