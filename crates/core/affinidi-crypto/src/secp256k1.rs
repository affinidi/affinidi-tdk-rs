//! secp256k1 key operations

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use k256::elliptic_curve::Generate;
use k256::{
    AffinePoint,
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::{FromSec1Point, ToSec1Point},
};

/// `elliptic-curve` 0.14 made `EncodedPoint` a generic alias for
/// `Sec1Point<C>`; pin it to this module's curve.
type EncodedPoint = k256::elliptic_curve::sec1::Sec1Point<k256::Secp256k1>;

use crate::{CryptoError, ECParams, JWK, KeyType, Params, error::Result};

/// Generated key pair with raw bytes and JWK representation
#[derive(Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
    pub jwk: JWK,
}

key_pair_hygiene!(jwk);

/// Generates a random secp256k1 key pair using the OS RNG.
///
/// This is the infallible counterpart to [`generate`] when no seed is needed.
pub fn generate_random() -> KeyPair {
    generate(None).expect("generate(None) is infallible")
}

/// Generates a secp256k1 key pair
pub fn generate(secret: Option<&[u8]>) -> Result<KeyPair> {
    let signing_key = match secret {
        Some(secret) => SigningKey::from_slice(secret).map_err(|e| {
            CryptoError::KeyError(format!("secp256k1 secret material isn't valid: {e}"))
        })?,
        None => SigningKey::generate(),
    };

    let verifying_key = VerifyingKey::from(&signing_key);
    let private_bytes = signing_key.to_bytes().to_vec();
    let private_d = BASE64_URL_SAFE_NO_PAD.encode(&private_bytes);
    let public_bytes = verifying_key.to_sec1_point(false).to_bytes().to_vec();

    Ok(KeyPair {
        key_type: KeyType::Secp256k1,
        private_bytes,
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::EC(ECParams {
                curve: "secp256k1".to_string(),
                x: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_sec1_point(false).x().unwrap()),
                y: BASE64_URL_SAFE_NO_PAD.encode(verifying_key.to_sec1_point(false).y().unwrap()),
                d: Some(private_d),
            }),
        },
    })
}

/// Generates a public JWK from secp256k1 raw bytes (compressed or uncompressed)
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    let ep = EncodedPoint::from_bytes(data)
        .map_err(|e| CryptoError::KeyError(format!("secp256k1 public key isn't valid: {e}")))?;

    // Convert to AffinePoint to validate the point is on the curve
    let ap: AffinePoint = AffinePoint::from_sec1_point(&ep)
        .into_option()
        .ok_or_else(|| {
            CryptoError::KeyError("Couldn't convert secp256k1 EncodedPoint to AffinePoint".into())
        })?;

    // Decompress to get x and y coordinates
    let ep = ap.to_sec1_point(false);

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
    fn secp256k1_key_pair_wipes_on_drop() {
        crate::key_pair_test_support::assert_zeroize_on_drop::<KeyPair>();
    }

    #[test]
    fn secp256k1_into_parts_moves_the_key() {
        let keypair = generate_random();
        let private = keypair.private_bytes.clone();
        let public = keypair.public_bytes.clone();
        let parts = keypair.into_parts();
        assert_eq!(parts.key_type, KeyType::Secp256k1);
        assert_eq!(parts.private_bytes.as_slice(), private.as_slice());
        assert_eq!(parts.public_bytes, public);
        crate::key_pair_test_support::assert_jwk_private_is(&parts.jwk, &private);
        crate::key_pair_test_support::assert_debug_hides_private(&format!("{parts:?}"), &private);
    }

    #[test]
    fn secp256k1_into_private_bytes_and_into_jwk() {
        let keypair = generate_random();
        let private = keypair.private_bytes.clone();
        assert_eq!(
            keypair.clone().into_private_bytes().as_slice(),
            private.as_slice()
        );
        crate::key_pair_test_support::assert_jwk_private_is(&keypair.into_jwk(), &private);
    }

    #[test]
    fn secp256k1_debug_hides_private_key() {
        let keypair = generate_random();
        crate::key_pair_test_support::assert_debug_hides_private(
            &format!("{keypair:?}"),
            &keypair.private_bytes,
        );
    }

    #[test]
    fn secp256k1_zeroize_wipes_private_key() {
        use zeroize::Zeroize;
        let mut keypair = generate_random();
        keypair.zeroize();
        assert!(keypair.private_bytes.is_empty());
        crate::key_pair_test_support::assert_jwk_private_wiped(&keypair.jwk);
    }

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
