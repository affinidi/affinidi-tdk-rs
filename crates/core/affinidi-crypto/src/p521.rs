//! P-521 (secp521r1) key operations
//!
//! Mirrors the [`crate::p384`] module but is built on `SecretKey` rather than
//! the ECDSA `SigningKey`, so it needs only the `arithmetic` feature of the
//! `p521` crate (P-521 key agreement, not signing, is what this stack uses).

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p521::{
    AffinePoint, EncodedPoint, SecretKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use rand_core::OsRng;

use crate::{CryptoError, ECParams, JWK, KeyType, Params, error::Result};

/// Generated key pair with raw bytes and JWK representation
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub key_type: KeyType,
    pub private_bytes: Vec<u8>,
    pub public_bytes: Vec<u8>,
    pub jwk: JWK,
}

/// Generates a random P-521 key pair using the OS RNG.
///
/// This is the infallible counterpart to [`generate`] when no seed is needed.
pub fn generate_random() -> KeyPair {
    generate(None).expect("generate(None) is infallible")
}

/// Generates a P-521 key pair
pub fn generate(secret: Option<&[u8]>) -> Result<KeyPair> {
    let secret_key = match secret {
        Some(secret) => SecretKey::from_slice(secret).map_err(|e| {
            CryptoError::KeyError(format!("P-521 secret material isn't valid: {e}"))
        })?,
        None => SecretKey::random(&mut OsRng),
    };

    let public_key = secret_key.public_key();
    let private_bytes = secret_key.to_bytes().to_vec();
    let ep = public_key.to_encoded_point(false);
    let public_bytes = ep.as_bytes().to_vec();

    Ok(KeyPair {
        key_type: KeyType::P521,
        private_bytes: private_bytes.clone(),
        public_bytes,
        jwk: JWK {
            key_id: None,
            params: Params::EC(ECParams {
                curve: "P-521".to_string(),
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
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    })
}

/// Generates a public JWK from P-521 raw bytes (compressed or uncompressed)
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    let ep = EncodedPoint::from_bytes(data)
        .map_err(|e| CryptoError::KeyError(format!("P-521 public key isn't valid: {e}")))?;

    // Convert to AffinePoint to validate the point is on the curve
    let ap: AffinePoint = AffinePoint::from_encoded_point(&ep)
        .into_option()
        .ok_or_else(|| {
            CryptoError::KeyError("Couldn't convert P-521 EncodedPoint to AffinePoint".into())
        })?;

    // Decompress to get x and y coordinates
    let ep = ap.to_encoded_point(false);

    Ok(JWK {
        key_id: None,
        params: Params::EC(ECParams {
            curve: "P-521".to_string(),
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
    fn generate_roundtrips_through_secret() {
        // Generate, then reload from the private bytes — the derived public
        // coordinates must match (proves load + public derivation agree).
        let kp = generate_random();
        let reloaded = generate(Some(&kp.private_bytes)).unwrap();
        assert_eq!(reloaded.public_bytes, kp.public_bytes);
        assert_eq!(reloaded.private_bytes, kp.private_bytes);
        // P-521 uncompressed SEC1 point: 0x04 || x(66) || y(66) = 133 bytes.
        assert_eq!(kp.public_bytes.len(), 133);
        assert_eq!(kp.private_bytes.len(), 66);
        match &kp.jwk.params {
            Params::EC(p) => assert_eq!(p.curve, "P-521"),
            _ => panic!("expected EC params"),
        }
    }

    #[test]
    fn public_jwk_from_uncompressed() {
        let kp = generate_random();
        let jwk = public_jwk(&kp.public_bytes).unwrap();
        match (&jwk.params, &kp.jwk.params) {
            (Params::EC(got), Params::EC(want)) => {
                assert_eq!(got.curve, "P-521");
                assert_eq!(got.x, want.x);
                assert_eq!(got.y, want.y);
                assert!(got.d.is_none());
            }
            _ => panic!("expected EC params"),
        }
    }
}
