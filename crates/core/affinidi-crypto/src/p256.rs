//! P-256 (secp256r1/prime256v1) key operations

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use p256::{
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

/// Generates a P-256 key pair
pub fn generate(secret: Option<&[u8]>) -> Result<KeyPair> {
    let signing_key = match secret {
        Some(secret) => SigningKey::from_slice(secret).map_err(|e| {
            CryptoError::KeyError(format!("P-256 secret material isn't valid: {e}"))
        })?,
        None => SigningKey::random(&mut OsRng),
    };

    let verifying_key = VerifyingKey::from(&signing_key);
    let private_bytes = signing_key.to_bytes().to_vec();
    let public_bytes = verifying_key.to_encoded_point(false).to_bytes().to_vec();

    Ok(KeyPair {
        key_type: KeyType::P256,
        private_bytes: private_bytes.clone(),
        public_bytes: public_bytes.clone(),
        jwk: JWK {
            key_id: None,
            params: Params::EC(ECParams {
                curve: "P-256".to_string(),
                x: BASE64_URL_SAFE_NO_PAD
                    .encode(verifying_key.to_encoded_point(false).x().unwrap()),
                y: BASE64_URL_SAFE_NO_PAD
                    .encode(verifying_key.to_encoded_point(false).y().unwrap()),
                d: Some(BASE64_URL_SAFE_NO_PAD.encode(&private_bytes)),
            }),
        },
    })
}

/// Generates a public JWK from P-256 raw bytes (compressed or uncompressed)
pub fn public_jwk(data: &[u8]) -> Result<JWK> {
    let ep = EncodedPoint::from_bytes(data)
        .map_err(|e| CryptoError::KeyError(format!("P-256 public key isn't valid: {e}")))?;

    // Convert to AffinePoint to validate the point is on the curve
    let ap: AffinePoint = AffinePoint::from_encoded_point(&ep)
        .into_option()
        .ok_or_else(|| {
            CryptoError::KeyError("Couldn't convert P-256 EncodedPoint to AffinePoint".into())
        })?;

    // Decompress to get x and y coordinates
    let ep = ap.to_encoded_point(false);

    Ok(JWK {
        key_id: None,
        params: Params::EC(ECParams {
            curve: "P-256".to_string(),
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

/// Sign data with a P-256 private key, producing an ES256 signature.
///
/// Returns the raw signature bytes (r || s, 64 bytes).
pub fn sign(private_key_bytes: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::{Signature, signature::Signer};

    let signing_key = SigningKey::from_slice(private_key_bytes)
        .map_err(|e| CryptoError::KeyError(format!("invalid P-256 private key: {e}")))?;

    let signature: Signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// Verify an ES256 signature with a P-256 public key.
///
/// `public_key_bytes` should be the uncompressed or compressed SEC1 encoding.
/// `signature_bytes` should be 64 bytes (r || s).
pub fn verify(public_key_bytes: &[u8], data: &[u8], signature_bytes: &[u8]) -> Result<bool> {
    use p256::ecdsa::{Signature, signature::Verifier};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .map_err(|e| CryptoError::KeyError(format!("invalid P-256 public key: {e}")))?;

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| CryptoError::KeyError(format!("invalid signature: {e}")))?;

    match verifying_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_from_secret() {
        let d = "0Dn-Cq97w8lVf0Fe6pQaynM8obOYaouDpRHUQlN9mXw";
        let x = "OqtR8tur0bXp3dpvHg8S4R_bjFEFGBfv4WKYU6o7llc";
        let y = "nPBTM3K9oYq4YyajBb7BTKCOZBWJIqvX0Cbokd03QK8";

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
            3, 127, 35, 88, 48, 221, 61, 239, 167, 34, 239, 26, 162, 73, 214, 160, 221, 187, 164,
            249, 144, 176, 129, 117, 56, 147, 63, 87, 54, 64, 101, 53, 66,
        ];

        let jwk = public_jwk(&bytes).unwrap();

        if let Params::EC(params) = &jwk.params {
            assert_eq!(params.curve, "P-256");
            assert!(params.d.is_none());
            assert_eq!(params.x, "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI");
            assert_eq!(params.y, "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU");
        } else {
            panic!("Expected EC params");
        }
    }

    #[test]
    fn sign_and_verify() {
        let keypair = generate(None).unwrap();
        let data = b"Hello, eIDAS 2.0!";

        let signature = sign(&keypair.private_bytes, data).unwrap();
        assert_eq!(signature.len(), 64); // r || s

        let valid = verify(&keypair.public_bytes, data, &signature).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_wrong_data_fails() {
        let keypair = generate(None).unwrap();
        let signature = sign(&keypair.private_bytes, b"correct").unwrap();

        let valid = verify(&keypair.public_bytes, b"wrong", &signature).unwrap();
        assert!(!valid);
    }

    #[test]
    fn verify_wrong_key_fails() {
        let keypair1 = generate(None).unwrap();
        let keypair2 = generate(None).unwrap();
        let data = b"test data";

        let signature = sign(&keypair1.private_bytes, data).unwrap();
        let valid = verify(&keypair2.public_bytes, data, &signature).unwrap();
        assert!(!valid);
    }
}
