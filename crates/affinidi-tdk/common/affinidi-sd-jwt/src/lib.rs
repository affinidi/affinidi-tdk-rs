/*!
 * SD-JWT (Selective Disclosure JWT) implementation.
 *
 * Implements [RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)
 * providing issuance, presentation, and verification of selectively disclosable JWTs.
 *
 * # SD-JWT Format
 *
 * An SD-JWT is serialized as:
 * ```text
 * <issuer-JWT>~<disclosure1>~<disclosure2>~...~[<KB-JWT>]
 * ```
 *
 * - The issuer JWT contains `_sd` arrays with digests replacing disclosable claims
 * - Each disclosure is a base64url-encoded JSON array: `[salt, claim_name, claim_value]`
 * - An optional Key Binding JWT (KB-JWT) proves holder possession
 *
 * # Modules
 *
 * - [`issuer`] — Create SD-JWTs from claims and disclosure frames
 * - [`holder`] — Create presentations by selecting disclosures
 * - [`verifier`] — Verify SD-JWT signatures and reconstruct claims
 * - [`disclosure`] — The atomic disclosure type
 * - [`hasher`] — Pluggable hash functions (SHA-256, SHA-384, SHA-512)
 * - [`signer`] — Pluggable JWT signing/verification traits
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

pub mod disclosure;
pub mod error;
pub mod hasher;
pub mod holder;
pub mod issuer;
pub mod signer;
pub mod verifier;

pub use disclosure::Disclosure;
pub use error::SdJwtError;
pub use hasher::{SdHasher, Sha256Hasher, Sha384Hasher, Sha512Hasher};
pub use holder::KbJwtInput;
pub use signer::{JwtSigner, JwtVerifier};
pub use verifier::{VerificationOptions, VerificationResult};

/// An SD-JWT: a signed JWT with selective disclosures and optional key binding.
#[derive(Debug, Clone)]
pub struct SdJwt {
    /// The issuer-signed compact JWS (header.payload.signature)
    pub jws: String,
    /// The selective disclosures
    pub disclosures: Vec<Disclosure>,
    /// Optional Key Binding JWT
    pub kb_jwt: Option<String>,
}

impl SdJwt {
    /// Serialize the SD-JWT to the compact format:
    /// `<jws>~<disclosure1>~<disclosure2>~...~[<kb_jwt>]`
    pub fn serialize(&self) -> String {
        let base = self.serialize_without_kb();
        if let Some(kb) = &self.kb_jwt {
            format!("{base}{kb}")
        } else {
            base
        }
    }

    /// Serialize the SD-JWT without the KB-JWT (used for `sd_hash` computation).
    ///
    /// Returns the format `<jws>~<d1>~<d2>~...~` (always ends with `~`).
    pub fn serialize_without_kb(&self) -> String {
        let mut parts = vec![self.jws.as_str()];
        let serialized_refs: Vec<&str> = self
            .disclosures
            .iter()
            .map(|d| d.serialized.as_str())
            .collect();
        parts.extend(serialized_refs);
        parts.join("~") + "~"
    }

    /// Parse a serialized SD-JWT string.
    pub fn parse(serialized: &str, hasher: &dyn SdHasher) -> Result<Self, SdJwtError> {
        if serialized.is_empty() {
            return Err(SdJwtError::InvalidFormat("empty input".into()));
        }

        let parts: Vec<&str> = serialized.split('~').collect();

        let jws = parts[0].to_string();

        // Validate JWS has 3 dot-separated parts
        if jws.split('.').count() != 3 {
            return Err(SdJwtError::InvalidFormat(
                "JWS must have 3 dot-separated parts".into(),
            ));
        }

        let mut disclosures = Vec::new();
        let mut kb_jwt = None;

        if parts.len() > 1 {
            let last = parts[parts.len() - 1];

            let disclosure_end = if last.is_empty() {
                parts.len() - 1
            } else if last.split('.').count() == 3 {
                kb_jwt = Some(last.to_string());
                parts.len() - 1
            } else {
                parts.len()
            };

            for &part in &parts[1..disclosure_end] {
                if !part.is_empty() {
                    let disclosure = Disclosure::parse(part, hasher)?;
                    disclosures.push(disclosure);
                }
            }
        }

        Ok(SdJwt {
            jws,
            disclosures,
            kb_jwt,
        })
    }

    /// Decode the JWT payload without verifying the signature.
    pub fn payload(&self) -> Result<Value, SdJwtError> {
        Self::decode_jwt_part(&self.jws, 1)
    }

    /// Decode the JWT header without verifying the signature.
    pub fn header(&self) -> Result<Value, SdJwtError> {
        Self::decode_jwt_part(&self.jws, 0)
    }

    /// Decode a specific part (0=header, 1=payload) from a compact JWS.
    fn decode_jwt_part(jws: &str, part_index: usize) -> Result<Value, SdJwtError> {
        let parts: Vec<&str> = jws.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(SdJwtError::InvalidFormat("invalid JWS format".into()));
        }

        let bytes = URL_SAFE_NO_PAD
            .decode(parts[part_index])
            .map_err(|e| SdJwtError::InvalidFormat(format!("JWT decode: {e}")))?;
        let value: Value = serde_json::from_slice(&bytes)?;
        Ok(value)
    }
}

impl std::fmt::Display for SdJwt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hasher::Sha256Hasher;
    use signer::test_utils::HmacSha256Signer;

    #[test]
    fn serialize_and_parse_roundtrip() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");

        let claims = serde_json::json!({
            "sub": "user123", "name": "John", "email": "john@example.com"
        });
        let frame = serde_json::json!({ "_sd": ["name", "email"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let serialized = sd_jwt.serialize();

        let parsed = SdJwt::parse(&serialized, &hasher).unwrap();
        assert_eq!(parsed.jws, sd_jwt.jws);
        assert_eq!(parsed.disclosures.len(), sd_jwt.disclosures.len());
        assert!(parsed.kb_jwt.is_none());
        assert_eq!(parsed.serialize(), serialized);
    }

    #[test]
    fn parse_empty_fails() {
        assert!(SdJwt::parse("", &Sha256Hasher).is_err());
    }

    #[test]
    fn parse_invalid_jws_fails() {
        assert!(SdJwt::parse("not-a-jwt~", &Sha256Hasher).is_err());
    }

    #[test]
    fn parse_jws_only() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");

        let claims = serde_json::json!({ "sub": "user123" });
        let frame = serde_json::json!({});

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let serialized = format!("{}~", sd_jwt.jws);
        let parsed = SdJwt::parse(&serialized, &hasher).unwrap();
        assert!(parsed.disclosures.is_empty());
        assert!(parsed.kb_jwt.is_none());
    }

    #[test]
    fn header_has_sd_jwt_typ() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let header = sd_jwt.header().unwrap();
        assert_eq!(header["typ"], "sd+jwt");
        assert_eq!(header["alg"], "HS256");
    }

    #[test]
    fn display_trait_matches_serialize() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.to_string(), sd_jwt.serialize());
    }

    #[test]
    fn serialize_without_kb_ends_with_tilde() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let without_kb = sd_jwt.serialize_without_kb();
        assert!(without_kb.ends_with('~'));
        // serialize() and serialize_without_kb() should match when no KB-JWT
        assert_eq!(without_kb, sd_jwt.serialize());
    }

    #[test]
    fn parse_with_kb_jwt() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(b"test-key-for-hmac-256-signing!!");
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });
        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "abc123",
            signer: &holder_signer,
            iat: 1700000000,
        };

        let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();
        let serialized = presentation.serialize();

        let parsed = SdJwt::parse(&serialized, &hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 1);
        assert!(parsed.kb_jwt.is_some());
    }
}
