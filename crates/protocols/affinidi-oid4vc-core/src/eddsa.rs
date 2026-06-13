/*!
 * EdDSA (Ed25519) JWT signer and verifier.
 *
 * Provides production-ready Ed25519 implementations of the
 * [`JwtSigner`](crate::jwt::JwtSigner) and
 * [`JwtVerifier`](crate::jwt::JwtVerifier) traits for use in SIOPv2,
 * OpenID4VCI, and OpenID4VP — the `EdDSA` JWS algorithm (RFC 8037).
 *
 * Ed25519 `did:key` is the dominant holder-key shape in the Affinidi stack,
 * so this is the natural companion to [`es256`](crate::es256): consumers that
 * sign or verify an OID4VCI key-binding proof (or any compact JWS) with an
 * Ed25519 key plug these in instead of hand-rolling `verify_strict`.
 *
 * Enabled via the `eddsa` feature flag.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::jwt::{JwtError, JwtSigner, JwtVerifier};

/// The JWS `alg` value for Ed25519 (RFC 8037 §3.1).
pub const ALG: &str = "EdDSA";

/// Ed25519 JWT signer wrapping a signing (private) key.
pub struct EdDsaSigner {
    signing_key: SigningKey,
    kid: Option<String>,
}

impl EdDsaSigner {
    /// Create a signer from the 32-byte Ed25519 seed (private key).
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, JwtError> {
        let seed: [u8; 32] = private_key
            .try_into()
            .map_err(|_| JwtError::Signing("Ed25519 private key must be 32 bytes".into()))?;
        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
            kid: None,
        })
    }

    /// Generate a new random Ed25519 key pair using the OS RNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut rand_core::OsRng)
    }

    /// Generate a new Ed25519 key pair using a caller-supplied RNG.
    ///
    /// Useful for tests that need deterministic keys via a seeded RNG.
    pub fn generate_with_rng<R>(rng: &mut R) -> Self
    where
        R: rand_core::CryptoRng + rand_core::RngCore,
    {
        Self {
            signing_key: SigningKey::generate(rng),
            kid: None,
        }
    }

    /// Set the key ID for the JWT header `kid`.
    pub fn with_kid(mut self, kid: impl Into<String>) -> Self {
        self.kid = Some(kid.into());
        self
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    /// The public key as an RFC 8037 OKP JWK `Value`.
    pub fn public_key_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(self.signing_key.verifying_key().to_bytes()),
        })
    }
}

impl JwtSigner for EdDsaSigner {
    fn algorithm(&self) -> &str {
        ALG
    }

    fn key_id(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, JwtError> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }
}

/// Ed25519 JWT verifier wrapping a verifying (public) key.
pub struct EdDsaVerifier {
    verifying_key: VerifyingKey,
}

impl EdDsaVerifier {
    /// Create a verifier from the 32-byte Ed25519 public key.
    pub fn from_bytes(public_key: &[u8]) -> Result<Self, JwtError> {
        let bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| JwtError::Verification("Ed25519 public key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| JwtError::Verification(format!("invalid Ed25519 public key: {e}")))?;
        Ok(Self { verifying_key })
    }

    /// Create a verifier from an RFC 8037 OKP JWK `Value` (`crv: "Ed25519"`).
    pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self, JwtError> {
        // RFC 8037: an Ed25519 JWK is `kty: "OKP"`, `crv: "Ed25519"`. Reject
        // a mismatched/missing `kty` so a malformed key (e.g. `kty: "EC"`)
        // can't slip through on the `crv` check alone.
        match jwk.get("kty").and_then(|v| v.as_str()) {
            Some("OKP") => {}
            Some(other) => {
                return Err(JwtError::Verification(format!(
                    "expected JWK kty OKP, got {other}"
                )));
            }
            None => return Err(JwtError::Verification("JWK missing kty".into())),
        }
        match jwk.get("crv").and_then(|v| v.as_str()) {
            Some("Ed25519") => {}
            Some(other) => {
                return Err(JwtError::Verification(format!(
                    "expected OKP crv Ed25519, got {other}"
                )));
            }
            None => return Err(JwtError::Verification("JWK missing crv".into())),
        }
        let x = jwk
            .get("x")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JwtError::Verification("JWK missing x".into()))?;
        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| JwtError::Verification(format!("x decode: {e}")))?;
        Self::from_bytes(&x_bytes)
    }
}

impl JwtVerifier for EdDsaVerifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        let sig = Signature::from_slice(signature)
            .map_err(|e| JwtError::Verification(format!("invalid signature: {e}")))?;
        // `verify_strict` rejects malleable / small-order-component signatures
        // (the stronger of dalek's two checks) — the right default for tokens.
        self.verifying_key
            .verify_strict(data, &sig)
            .map_err(|_| JwtError::Verification("EdDSA signature verification failed".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::{decode_compact_jws_verified_with_algs, encode_compact_jws};
    use serde_json::json;

    #[test]
    fn eddsa_sign_verify_jwt() {
        let signer = EdDsaSigner::from_bytes(&[7u8; 32]).unwrap().with_kid("k1");
        let verifier = EdDsaVerifier::from_bytes(&signer.public_key_bytes()).unwrap();

        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": "k1"});
        let payload = json!({"sub": "user123", "name": "Alice"});

        let jws = encode_compact_jws(&header, &payload, &signer).unwrap();
        let (decoded_header, decoded_payload) =
            decode_compact_jws_verified_with_algs(&jws, &verifier, &["EdDSA"]).unwrap();

        assert_eq!(decoded_header["alg"], "EdDSA");
        assert_eq!(decoded_payload["sub"], "user123");
    }

    #[test]
    fn eddsa_wrong_key_fails() {
        let signer = EdDsaSigner::from_bytes(&[1u8; 32]).unwrap();
        let other = EdDsaSigner::from_bytes(&[2u8; 32]).unwrap();
        let verifier = EdDsaVerifier::from_bytes(&other.public_key_bytes()).unwrap();

        let jws = encode_compact_jws(&json!({"alg": "EdDSA"}), &json!({"x": 1}), &signer).unwrap();
        assert!(decode_compact_jws_verified_with_algs(&jws, &verifier, &["EdDSA"]).is_err());
    }

    #[test]
    fn eddsa_from_jwk_roundtrip() {
        let signer = EdDsaSigner::from_bytes(&[3u8; 32]).unwrap();
        let jwk = signer.public_key_jwk();
        assert_eq!(jwk["kty"], "OKP");
        assert_eq!(jwk["crv"], "Ed25519");

        let verifier = EdDsaVerifier::from_jwk(&jwk).unwrap();
        let jws =
            encode_compact_jws(&json!({"alg": "EdDSA"}), &json!({"test": true}), &signer).unwrap();
        let (_, payload) =
            decode_compact_jws_verified_with_algs(&jws, &verifier, &["EdDSA"]).unwrap();
        assert_eq!(payload["test"], true);
    }

    #[test]
    fn eddsa_from_jwk_rejects_wrong_curve() {
        let jwk = json!({"kty": "OKP", "crv": "X25519", "x": "AAAA"});
        assert!(EdDsaVerifier::from_jwk(&jwk).is_err());
    }

    #[test]
    fn eddsa_from_jwk_rejects_wrong_kty() {
        // `crv` claims Ed25519 but `kty` is EC — malformed, must be rejected.
        let jwk = json!({"kty": "EC", "crv": "Ed25519", "x": "AAAA"});
        assert!(EdDsaVerifier::from_jwk(&jwk).is_err());
    }

    #[test]
    fn eddsa_signature_is_64_bytes() {
        let signer = EdDsaSigner::from_bytes(&[5u8; 32]).unwrap();
        assert_eq!(signer.sign(b"test data").unwrap().len(), 64);
    }

    #[test]
    fn eddsa_generate_produces_working_keypair() {
        let signer = EdDsaSigner::generate();
        let verifier = EdDsaVerifier::from_bytes(&signer.public_key_bytes()).unwrap();
        let jws = encode_compact_jws(&json!({"alg": "EdDSA"}), &json!({"ok": 1}), &signer).unwrap();
        assert!(decode_compact_jws_verified_with_algs(&jws, &verifier, &["EdDSA"]).is_ok());
    }

    #[test]
    fn eddsa_from_bytes_rejects_wrong_length() {
        assert!(EdDsaSigner::from_bytes(&[0u8; 16]).is_err());
        assert!(EdDsaVerifier::from_bytes(&[0u8; 16]).is_err());
    }
}
