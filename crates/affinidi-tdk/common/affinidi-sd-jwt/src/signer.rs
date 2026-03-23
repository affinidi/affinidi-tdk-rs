/*!
 * Pluggable signing and verification traits for SD-JWT.
 *
 * These are intentionally minimal and algorithm-agnostic so that
 * callers can plug in HMAC, RSA, ECDSA, EdDSA, or external KMS.
 */

use crate::error::SdJwtError;

/// Trait for signing JWT payloads.
///
/// Implementations produce a compact JWS (header.payload.signature).
pub trait JwtSigner: Send + Sync {
    /// The JWS algorithm name for the JWT header `alg` field (e.g. "ES256", "EdDSA").
    fn algorithm(&self) -> &str;

    /// Optional key ID for the JWT header `kid` field.
    fn key_id(&self) -> Option<&str> {
        None
    }

    /// Sign the compact JWS signing input (`header_b64.payload_b64`) and return
    /// the complete compact JWS string (`header_b64.payload_b64.signature_b64`).
    fn sign_jwt(
        &self,
        header: &serde_json::Value,
        payload: &serde_json::Value,
    ) -> Result<String, SdJwtError>;
}

/// Trait for verifying JWT signatures.
///
/// Implementations verify a compact JWS and return the decoded payload.
pub trait JwtVerifier: Send + Sync {
    /// Verify the compact JWS string and return the decoded payload.
    /// Should check the signature and validate the `alg` header.
    fn verify_jwt(&self, jws: &str) -> Result<serde_json::Value, SdJwtError>;
}

/// HMAC-SHA256 test utilities for unit testing.
///
/// **WARNING:** These implementations are for testing only:
/// - Signature comparison is NOT constant-time (vulnerable to timing attacks)
/// - HMAC is a symmetric algorithm (not suitable for SD-JWT in production)
/// - Use asymmetric algorithms (ES256, EdDSA) for production SD-JWT
#[cfg(any(test, feature = "_test-utils"))]
pub mod test_utils {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use sha2::Sha256;

    /// A simple HMAC-SHA256 signer for unit tests.
    ///
    /// **Not for production use.** Use asymmetric algorithms (ES256, EdDSA) instead.
    pub struct HmacSha256Signer {
        pub key: Vec<u8>,
    }

    impl HmacSha256Signer {
        pub fn new(key: &[u8]) -> Self {
            Self { key: key.to_vec() }
        }

        fn hmac_sha256(&self, data: &[u8]) -> Vec<u8> {
            use sha2::Digest;
            let mut key_block = [0u8; 64];
            if self.key.len() <= 64 {
                key_block[..self.key.len()].copy_from_slice(&self.key);
            } else {
                let hash = Sha256::digest(&self.key);
                key_block[..32].copy_from_slice(&hash);
            }

            let mut ipad = [0x36u8; 64];
            let mut opad = [0x5cu8; 64];
            for i in 0..64 {
                ipad[i] ^= key_block[i];
                opad[i] ^= key_block[i];
            }

            let mut inner_hasher = Sha256::new();
            inner_hasher.update(&ipad);
            inner_hasher.update(data);
            let inner_hash = inner_hasher.finalize();

            let mut outer_hasher = Sha256::new();
            outer_hasher.update(&opad);
            outer_hasher.update(&inner_hash);
            outer_hasher.finalize().to_vec()
        }
    }

    impl JwtSigner for HmacSha256Signer {
        fn algorithm(&self) -> &str {
            "HS256"
        }

        fn sign_jwt(
            &self,
            header: &serde_json::Value,
            payload: &serde_json::Value,
        ) -> Result<String, SdJwtError> {
            let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(header)?.as_bytes());
            let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_string(payload)?.as_bytes());
            let signing_input = format!("{header_b64}.{payload_b64}");
            let sig = self.hmac_sha256(signing_input.as_bytes());
            let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);
            Ok(format!("{signing_input}.{sig_b64}"))
        }
    }

    /// A simple HMAC-SHA256 verifier for unit tests.
    ///
    /// **Not for production use.** Signature comparison is NOT constant-time.
    pub struct HmacSha256Verifier {
        signer: HmacSha256Signer,
    }

    impl HmacSha256Verifier {
        pub fn new(key: &[u8]) -> Self {
            Self {
                signer: HmacSha256Signer::new(key),
            }
        }
    }

    impl JwtVerifier for HmacSha256Verifier {
        fn verify_jwt(&self, jws: &str) -> Result<serde_json::Value, SdJwtError> {
            let parts: Vec<&str> = jws.splitn(3, '.').collect();
            if parts.len() != 3 {
                return Err(SdJwtError::Verification("invalid JWS format".into()));
            }

            let signing_input = format!("{}.{}", parts[0], parts[1]);
            let expected_sig = self.signer.hmac_sha256(signing_input.as_bytes());
            let actual_sig = URL_SAFE_NO_PAD
                .decode(parts[2])
                .map_err(|e| SdJwtError::Verification(format!("sig decode: {e}")))?;

            // WARNING: Not constant-time. For testing only.
            if expected_sig != actual_sig {
                return Err(SdJwtError::Verification("signature mismatch".into()));
            }

            let payload_bytes = URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|e| SdJwtError::Verification(format!("payload decode: {e}")))?;
            let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)?;
            Ok(payload)
        }
    }
}
