/*!
 * ES256 (ECDSA P-256) JWT signer and verifier.
 *
 * Provides production-ready P-256 ECDSA implementations of the
 * `JwtSigner` and `JwtVerifier` traits for use in SIOPv2, OpenID4VCI,
 * and OpenID4VP protocols.
 *
 * Enabled via the `es256` feature flag.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};

use crate::jwt::{JwtError, JwtSigner, JwtVerifier};

/// ES256 JWT signer using a P-256 private key.
pub struct Es256Signer {
    signing_key: SigningKey,
    kid: Option<String>,
}

impl Es256Signer {
    /// Create a signer from raw P-256 private key bytes (32 bytes).
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, JwtError> {
        let signing_key = SigningKey::from_slice(private_key)
            .map_err(|e| JwtError::Signing(format!("invalid P-256 key: {e}")))?;
        Ok(Self {
            signing_key,
            kid: None,
        })
    }

    /// Generate a new random P-256 key pair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        Self {
            signing_key,
            kid: None,
        }
    }

    /// Set the key ID for the JWT header.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// Get the public key as uncompressed SEC1 bytes.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        VerifyingKey::from(&self.signing_key)
            .to_encoded_point(false)
            .to_bytes()
            .to_vec()
    }

    /// Get the public key as a JWK Value.
    pub fn public_key_jwk(&self) -> serde_json::Value {
        let vk = VerifyingKey::from(&self.signing_key);
        let point = vk.to_encoded_point(false);

        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()),
            "y": URL_SAFE_NO_PAD.encode(point.y().unwrap()),
        })
    }
}

impl JwtSigner for Es256Signer {
    fn algorithm(&self) -> &str {
        "ES256"
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// ES256 JWT verifier using a P-256 public key.
pub struct Es256Verifier {
    verifying_key: VerifyingKey,
}

impl Es256Verifier {
    /// Create a verifier from uncompressed or compressed SEC1 public key bytes.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self, JwtError> {
        let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|e| JwtError::Verification(format!("invalid P-256 public key: {e}")))?;
        Ok(Self { verifying_key })
    }

    /// Create a verifier from a JWK Value containing EC P-256 key material.
    pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self, JwtError> {
        let x = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::Verification("missing x coordinate".into()))?;
        let y = jwk
            .get("y")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::Verification("missing y coordinate".into()))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| JwtError::Verification(format!("x decode: {e}")))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|e| JwtError::Verification(format!("y decode: {e}")))?;

        // Build uncompressed point: 0x04 || x || y
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&x_bytes);
        uncompressed.extend_from_slice(&y_bytes);

        Self::from_bytes(&uncompressed)
    }
}

impl JwtVerifier for Es256Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| JwtError::Verification(format!("invalid signature: {e}")))?;

        self.verifying_key
            .verify(data, &sig)
            .map_err(|_| JwtError::Verification("ES256 signature verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{decode_compact_jws_verified, encode_compact_jws};
    use serde_json::json;

    #[test]
    fn es256_sign_verify_jwt() {
        let signer = Es256Signer::generate().with_kid("test-key-1");
        let verifier = Es256Verifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let header = json!({"alg": "ES256", "typ": "JWT", "kid": "test-key-1"});
        let payload = json!({"sub": "user123", "name": "Alice"});

        let jws = encode_compact_jws(&header, &payload, &signer).unwrap();
        let (decoded_header, decoded_payload) =
            decode_compact_jws_verified(&jws, &verifier).unwrap();

        assert_eq!(decoded_header["alg"], "ES256");
        assert_eq!(decoded_payload["sub"], "user123");
    }

    #[test]
    fn es256_wrong_key_fails() {
        let signer = Es256Signer::generate();
        let wrong_signer = Es256Signer::generate();
        let verifier = Es256Verifier::from_bytes(&wrong_signer.public_key_bytes()).unwrap();

        let jws = encode_compact_jws(&json!({"alg": "ES256"}), &json!({"x": 1}), &signer).unwrap();

        assert!(decode_compact_jws_verified(&jws, &verifier).is_err());
    }

    #[test]
    fn es256_from_jwk() {
        let signer = Es256Signer::generate();
        let jwk = signer.public_key_jwk();

        let verifier = Es256Verifier::from_jwk(&jwk).unwrap();

        let jws =
            encode_compact_jws(&json!({"alg": "ES256"}), &json!({"test": true}), &signer).unwrap();

        let (_, payload) = decode_compact_jws_verified(&jws, &verifier).unwrap();
        assert_eq!(payload["test"], true);
    }

    #[test]
    fn es256_public_key_jwk_format() {
        let signer = Es256Signer::generate();
        let jwk = signer.public_key_jwk();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk.get("x").is_some());
        assert!(jwk.get("y").is_some());
    }

    #[test]
    fn es256_signature_is_64_bytes() {
        let signer = Es256Signer::generate();
        let sig = signer.sign(b"test data").unwrap();
        assert_eq!(sig.len(), 64);
    }
}
