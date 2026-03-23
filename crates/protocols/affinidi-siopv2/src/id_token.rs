/*!
 * Self-Issued ID Token per SIOPv2 spec.
 *
 * The critical invariant: `iss == sub` — this signals the token is self-issued.
 *
 * # Subject Types
 *
 * - **JWK Thumbprint**: `sub` = base64url(SHA-256(canonical_jwk)),
 *   `sub_jwk` claim MUST be present
 * - **DID**: `sub` = DID string (e.g., "did:key:z6Mk..."),
 *   `sub_jwk` MUST NOT be present
 */

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, SiopError};

/// A Self-Issued ID Token per SIOPv2.
///
/// The `iss` and `sub` claims MUST be identical, signaling self-issuance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfIssuedIdToken {
    /// Issuer — MUST equal `sub` for self-issued tokens.
    pub iss: String,
    /// Subject — JWK Thumbprint URI or DID.
    pub sub: String,
    /// Audience — MUST contain the RP's `client_id`.
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: i64,
    /// Issued-at time (Unix timestamp).
    pub iat: i64,
    /// Nonce from the authorization request (replay protection).
    pub nonce: String,
    /// Public key for JWK Thumbprint subjects. MUST NOT be present for DID subjects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub_jwk: Option<Value>,
    /// Time of authentication (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    /// Authentication context class reference (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acr: Option<String>,
    /// Authentication methods references (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amr: Option<Vec<String>>,
    /// Additional claims (name, email, etc. — self-attested).
    #[serde(flatten)]
    pub additional_claims: serde_json::Map<String, Value>,
}

impl SelfIssuedIdToken {
    /// Whether this is a DID-based subject (vs JWK Thumbprint).
    pub fn is_did_subject(&self) -> bool {
        self.sub.starts_with("did:")
    }

    /// Whether this is a JWK Thumbprint subject.
    pub fn is_jwk_thumbprint_subject(&self) -> bool {
        self.sub_jwk.is_some()
    }

    /// Validate the structural integrity of the ID Token.
    ///
    /// Checks:
    /// 1. `iss == sub` (self-issued invariant)
    /// 2. `sub_jwk` present iff JWK Thumbprint subject
    /// 3. For JWK Thumbprint: `sub` matches the thumbprint of `sub_jwk`
    /// 4. Token not expired
    /// 5. Nonce is non-empty
    pub fn validate(&self, expected_client_id: &str, expected_nonce: &str) -> Result<()> {
        // Step 1: iss == sub
        if self.iss != self.sub {
            return Err(SiopError::IssSubMismatch);
        }

        // Step 2: aud matches client_id
        if self.aud != expected_client_id {
            return Err(SiopError::AudienceMismatch {
                expected: expected_client_id.to_string(),
                actual: self.aud.clone(),
            });
        }

        // Step 3: nonce matches
        if self.nonce != expected_nonce {
            return Err(SiopError::NonceMismatch);
        }

        // Step 4: not expired
        let now = Utc::now().timestamp();
        if now > self.exp {
            return Err(SiopError::Expired);
        }

        // Step 5: sub_jwk consistency
        if self.is_did_subject() {
            if self.sub_jwk.is_some() {
                return Err(SiopError::InvalidIdToken(
                    "sub_jwk must not be present for DID subjects".into(),
                ));
            }
        } else if let Some(ref jwk) = self.sub_jwk {
            // Verify JWK Thumbprint matches sub
            let thumbprint = affinidi_oid4vc_core::compute_jwk_thumbprint(jwk)
                .ok_or_else(|| SiopError::InvalidIdToken("cannot compute JWK Thumbprint".into()))?;
            if self.sub != thumbprint {
                return Err(SiopError::ThumbprintMismatch);
            }
        } else {
            return Err(SiopError::InvalidIdToken(
                "sub_jwk required for non-DID subjects".into(),
            ));
        }

        Ok(())
    }
}

/// Builder for constructing `SelfIssuedIdToken` instances.
pub struct IdTokenBuilder {
    aud: String,
    nonce: String,
    sub: Option<String>,
    sub_jwk: Option<Value>,
    exp_seconds: i64,
    additional_claims: serde_json::Map<String, Value>,
}

impl IdTokenBuilder {
    /// Create a new builder with required fields.
    ///
    /// * `client_id` — The RP's client identifier (becomes `aud`)
    /// * `nonce` — The nonce from the authorization request
    pub fn new(client_id: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            aud: client_id.into(),
            nonce: nonce.into(),
            sub: None,
            sub_jwk: None,
            exp_seconds: 300, // 5 minutes default
            additional_claims: serde_json::Map::new(),
        }
    }

    /// Set the subject as a JWK Thumbprint.
    ///
    /// Computes the thumbprint and sets both `sub` and `sub_jwk`.
    pub fn with_jwk_thumbprint(mut self, jwk: Value) -> Result<Self> {
        let thumbprint = affinidi_oid4vc_core::compute_jwk_thumbprint(&jwk).ok_or_else(|| {
            SiopError::InvalidIdToken("cannot compute JWK Thumbprint from provided key".into())
        })?;
        self.sub = Some(thumbprint);
        self.sub_jwk = Some(jwk);
        Ok(self)
    }

    /// Set the subject as a DID.
    pub fn with_did(mut self, did: impl Into<String>) -> Self {
        self.sub = Some(did.into());
        self.sub_jwk = None;
        self
    }

    /// Set the expiration time in seconds from now.
    pub fn expires_in(mut self, seconds: i64) -> Self {
        self.exp_seconds = seconds;
        self
    }

    /// Add a self-attested claim (name, email, etc.).
    pub fn claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.additional_claims.insert(key.into(), value);
        self
    }

    /// Build the ID Token.
    pub fn build(self) -> Result<SelfIssuedIdToken> {
        let sub = self.sub.ok_or_else(|| {
            SiopError::InvalidIdToken(
                "subject must be set (via with_did or with_jwk_thumbprint)".into(),
            )
        })?;

        let now = Utc::now().timestamp();

        Ok(SelfIssuedIdToken {
            iss: sub.clone(), // iss == sub
            sub,
            aud: self.aud,
            exp: now + self.exp_seconds,
            iat: now,
            nonce: self.nonce,
            sub_jwk: self.sub_jwk,
            auth_time: Some(now),
            acr: None,
            amr: None,
            additional_claims: self.additional_claims,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_jwk() -> Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        })
    }

    #[test]
    fn build_jwk_thumbprint_token() {
        let token = IdTokenBuilder::new("https://rp.example.com", "nonce123")
            .with_jwk_thumbprint(test_jwk())
            .unwrap()
            .expires_in(600)
            .build()
            .unwrap();

        assert_eq!(token.iss, token.sub);
        assert_eq!(token.aud, "https://rp.example.com");
        assert_eq!(token.nonce, "nonce123");
        assert!(token.sub_jwk.is_some());
        assert!(!token.is_did_subject());
        assert!(token.is_jwk_thumbprint_subject());
    }

    #[test]
    fn build_did_token() {
        let token = IdTokenBuilder::new("https://rp.example.com", "nonce456")
            .with_did("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")
            .build()
            .unwrap();

        assert_eq!(token.iss, token.sub);
        assert_eq!(
            token.sub,
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        );
        assert!(token.sub_jwk.is_none());
        assert!(token.is_did_subject());
    }

    #[test]
    fn validate_jwk_thumbprint_token() {
        let token = IdTokenBuilder::new("rp-client-id", "test-nonce")
            .with_jwk_thumbprint(test_jwk())
            .unwrap()
            .build()
            .unwrap();

        assert!(token.validate("rp-client-id", "test-nonce").is_ok());
    }

    #[test]
    fn validate_did_token() {
        let token = IdTokenBuilder::new("rp-client-id", "test-nonce")
            .with_did("did:key:z6Mk...")
            .build()
            .unwrap();

        assert!(token.validate("rp-client-id", "test-nonce").is_ok());
    }

    #[test]
    fn validate_iss_sub_mismatch_fails() {
        let mut token = IdTokenBuilder::new("rp", "n")
            .with_did("did:key:abc")
            .build()
            .unwrap();

        token.iss = "different".into();
        assert!(matches!(
            token.validate("rp", "n"),
            Err(SiopError::IssSubMismatch)
        ));
    }

    #[test]
    fn validate_wrong_audience_fails() {
        let token = IdTokenBuilder::new("correct-rp", "n")
            .with_did("did:key:abc")
            .build()
            .unwrap();

        assert!(matches!(
            token.validate("wrong-rp", "n"),
            Err(SiopError::AudienceMismatch { .. })
        ));
    }

    #[test]
    fn validate_wrong_nonce_fails() {
        let token = IdTokenBuilder::new("rp", "correct-nonce")
            .with_did("did:key:abc")
            .build()
            .unwrap();

        assert!(matches!(
            token.validate("rp", "wrong-nonce"),
            Err(SiopError::NonceMismatch)
        ));
    }

    #[test]
    fn validate_expired_fails() {
        let mut token = IdTokenBuilder::new("rp", "n")
            .with_did("did:key:abc")
            .build()
            .unwrap();

        token.exp = Utc::now().timestamp() - 100;
        assert!(matches!(token.validate("rp", "n"), Err(SiopError::Expired)));
    }

    #[test]
    fn validate_did_with_sub_jwk_fails() {
        let mut token = IdTokenBuilder::new("rp", "n")
            .with_did("did:key:abc")
            .build()
            .unwrap();

        token.sub_jwk = Some(test_jwk());
        assert!(token.validate("rp", "n").is_err());
    }

    #[test]
    fn token_serialization_roundtrip() {
        let token = IdTokenBuilder::new("rp", "n")
            .with_did("did:key:abc")
            .claim("name", json!("Alice"))
            .claim("email", json!("alice@example.com"))
            .build()
            .unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let parsed: SelfIssuedIdToken = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.iss, token.iss);
        assert_eq!(parsed.sub, token.sub);
        assert_eq!(parsed.additional_claims["name"], "Alice");
        assert_eq!(parsed.additional_claims["email"], "alice@example.com");
    }

    #[test]
    fn build_without_subject_fails() {
        let result = IdTokenBuilder::new("rp", "n").build();
        assert!(result.is_err());
    }
}
