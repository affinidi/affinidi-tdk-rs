/*!
 * SD-JWT Verification: verify issuer signature, reconstruct claims,
 * and optionally verify Key Binding JWT.
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::SdJwt;
use crate::error::{Result, SdJwtError};
use crate::hasher::SdHasher;
use crate::holder::resolve_claims;
use crate::signer::JwtVerifier;

/// Options for SD-JWT verification.
#[derive(Debug, Default)]
pub struct VerificationOptions<'a> {
    /// Whether to verify the Key Binding JWT.
    pub verify_kb: bool,
    /// Expected `aud` in the KB-JWT (required if `verify_kb` is true).
    pub expected_audience: Option<&'a str>,
    /// Expected `nonce` in the KB-JWT (required if `verify_kb` is true).
    pub expected_nonce: Option<&'a str>,
}

/// Result of SD-JWT verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// The fully resolved claims (with disclosed values restored).
    pub claims: Value,
    /// Whether the KB-JWT was verified (`None` if no KB-JWT present).
    pub kb_verified: Option<bool>,
}

impl VerificationResult {
    /// Returns true if verification succeeded and any present KB-JWT was verified.
    pub fn is_verified(&self) -> bool {
        self.kb_verified.unwrap_or(true)
    }
}

/// Verify an SD-JWT presentation.
///
/// # Arguments
///
/// * `sd_jwt` - The parsed SD-JWT to verify
/// * `issuer_verifier` - Verifies the issuer's JWS signature
/// * `hasher` - The hash function (must match `_sd_alg` in the payload)
/// * `options` - Verification options (KB-JWT verification, audience, nonce)
/// * `holder_verifier` - Optional verifier for the KB-JWT signature (required if `verify_kb` is true)
///
/// # Errors
///
/// Returns an error if:
/// - The issuer JWS signature is invalid
/// - `_sd_alg` in the payload doesn't match the provided hasher
/// - Duplicate disclosures are detected (RFC 9901 §8.1)
/// - A disclosure digest is not found in the payload
/// - KB-JWT verification is requested but fails (missing cnf, sd_hash mismatch, etc.)
pub fn verify(
    sd_jwt: &SdJwt,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerificationOptions,
    holder_verifier: Option<&dyn JwtVerifier>,
) -> Result<VerificationResult> {
    // 1. Verify the issuer JWS
    let payload = issuer_verifier.verify_jwt(&sd_jwt.jws)?;

    // 2. Validate _sd_alg matches
    if let Some(alg) = payload.get("_sd_alg").and_then(|v| v.as_str())
        && alg != hasher.alg_name()
    {
        return Err(SdJwtError::Verification(format!(
            "_sd_alg mismatch: expected {}, got {alg}",
            hasher.alg_name()
        )));
    }

    // 3. Check for duplicate disclosures (S3, RFC 9901 §8.1)
    check_duplicate_disclosures(&sd_jwt.disclosures)?;

    // 4. Verify disclosure digests match the _sd array
    verify_disclosure_digests(&payload, &sd_jwt.disclosures, hasher)?;

    // 5. Resolve disclosed claims
    let claims = resolve_claims(&payload, &sd_jwt.disclosures)?;

    // 6. Verify KB-JWT if requested
    let kb_verified = if options.verify_kb {
        if let Some(kb_jwt_str) = &sd_jwt.kb_jwt {
            // Extract cnf.jwk from payload
            let _cnf_jwk = payload
                .get("cnf")
                .and_then(|v| v.get("jwk"))
                .ok_or_else(|| {
                    SdJwtError::KeyBinding(
                        "cnf.jwk required in payload for key binding verification".into(),
                    )
                })?;

            // Verify KB-JWT signature if a holder verifier is provided (S5)
            let kb_payload = if let Some(hv) = holder_verifier {
                hv.verify_jwt(kb_jwt_str)?
            } else {
                decode_jwt_payload(kb_jwt_str)?
            };

            // Verify sd_hash
            let expected_sd_hash = hasher.hash_b64(sd_jwt.serialize_without_kb().as_bytes());
            let actual_sd_hash = kb_payload
                .get("sd_hash")
                .and_then(|v| v.as_str())
                .ok_or_else(|| SdJwtError::KeyBinding("sd_hash missing in KB-JWT".into()))?;

            if actual_sd_hash != expected_sd_hash {
                return Err(SdJwtError::KeyBinding(format!(
                    "sd_hash mismatch: expected {expected_sd_hash}, got {actual_sd_hash}"
                )));
            }

            // Verify audience
            if let Some(expected_aud) = options.expected_audience {
                let actual_aud = kb_payload
                    .get("aud")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SdJwtError::KeyBinding("aud missing in KB-JWT".into()))?;
                if actual_aud != expected_aud {
                    return Err(SdJwtError::KeyBinding(format!(
                        "aud mismatch: expected {expected_aud}, got {actual_aud}"
                    )));
                }
            }

            // Verify nonce
            if let Some(expected_n) = options.expected_nonce {
                let actual_nonce = kb_payload
                    .get("nonce")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| SdJwtError::KeyBinding("nonce missing in KB-JWT".into()))?;
                if actual_nonce != expected_n {
                    return Err(SdJwtError::KeyBinding(format!(
                        "nonce mismatch: expected {expected_n}, got {actual_nonce}"
                    )));
                }
            }

            Some(true)
        } else {
            return Err(SdJwtError::KeyBinding(
                "key binding verification requested but no KB-JWT present".into(),
            ));
        }
    } else {
        sd_jwt.kb_jwt.as_ref().map(|_| false)
    };

    Ok(VerificationResult {
        claims,
        kb_verified,
    })
}

/// Check for duplicate disclosure digests (RFC 9901 §8.1).
fn check_duplicate_disclosures(disclosures: &[crate::disclosure::Disclosure]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for d in disclosures {
        if !seen.insert(&d.digest) {
            return Err(SdJwtError::Verification(format!(
                "duplicate disclosure digest: {}",
                d.digest
            )));
        }
    }
    Ok(())
}

/// Verify that all disclosure digests appear in the payload's _sd arrays.
fn verify_disclosure_digests(
    payload: &Value,
    disclosures: &[crate::disclosure::Disclosure],
    hasher: &dyn SdHasher,
) -> Result<()> {
    let mut all_digests = std::collections::HashSet::new();
    collect_digests(payload, &mut all_digests);

    for disclosure in disclosures {
        let expected_digest = hasher.hash_b64(disclosure.serialized.as_bytes());
        if !all_digests.contains(expected_digest.as_str()) {
            return Err(SdJwtError::Verification(format!(
                "disclosure digest not found in payload: {expected_digest}",
            )));
        }
    }

    Ok(())
}

/// Recursively collect all digest strings from _sd arrays and {"...": digest} entries.
fn collect_digests(value: &Value, digests: &mut std::collections::HashSet<String>) {
    match value {
        Value::Object(obj) => {
            if let Some(sd_array) = obj.get("_sd").and_then(|v| v.as_array()) {
                for item in sd_array {
                    if let Some(s) = item.as_str() {
                        digests.insert(s.to_string());
                    }
                }
            }

            if let Some(digest) = obj.get("...").and_then(|v| v.as_str()) {
                digests.insert(digest.to_string());
            }

            for (key, val) in obj {
                if key != "_sd" {
                    collect_digests(val, digests);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                collect_digests(item, digests);
            }
        }
        _ => {}
    }
}

/// Decode a JWT payload without verifying the signature.
fn decode_jwt_payload(jws: &str) -> Result<Value> {
    let parts: Vec<&str> = jws.splitn(3, '.').collect();
    if parts.len() != 3 {
        return Err(SdJwtError::InvalidFormat("invalid JWT format".into()));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| SdJwtError::InvalidFormat(format!("JWT payload decode: {e}")))?;
    let payload: Value = serde_json::from_slice(&payload_bytes)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::disclosure::Disclosure;
    use crate::hasher::Sha256Hasher;
    use crate::holder::{self, KbJwtInput};
    use crate::issuer;
    use crate::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};

    fn test_key() -> &'static [u8] {
        b"test-key-for-hmac-256-signing!!"
    }

    fn default_opts() -> VerificationOptions<'static> {
        VerificationOptions::default()
    }

    #[test]
    fn verify_simple_sd_jwt() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({
            "sub": "user123", "given_name": "John", "family_name": "Doe"
        });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let result = verify(&sd_jwt, &jwt_verifier, &hasher, &default_opts(), None).unwrap();

        assert!(result.is_verified());
        assert_eq!(result.claims["given_name"], "John");
        assert_eq!(result.claims["family_name"], "Doe");
    }

    #[test]
    fn verify_partial_disclosure() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({
            "sub": "user123", "given_name": "John", "family_name": "Doe"
        });
        let frame = serde_json::json!({ "_sd": ["given_name", "family_name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let selected = holder::select_disclosures(&sd_jwt, &["given_name"]);
        let presentation = holder::present(&sd_jwt, &selected, None, &hasher).unwrap();

        let result = verify(&presentation, &jwt_verifier, &hasher, &default_opts(), None).unwrap();
        assert!(result.is_verified());
        assert_eq!(result.claims["given_name"], "John");
        assert!(result.claims.get("family_name").is_none());
    }

    #[test]
    fn verify_zero_disclosures() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let presentation = holder::present(&sd_jwt, &[], None, &hasher).unwrap();

        let result = verify(&presentation, &jwt_verifier, &hasher, &default_opts(), None).unwrap();
        assert!(result.is_verified());
        assert!(result.claims.get("name").is_none());
    }

    #[test]
    fn verify_invalid_signature_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let wrong_verifier = HmacSha256Verifier::new(b"wrong-key-for-hmac-256-signing!");

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let result = verify(&sd_jwt, &wrong_verifier, &hasher, &default_opts(), None);
        assert!(result.is_err());
    }

    #[test]
    fn verify_duplicate_disclosure_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();

        // Duplicate the disclosure
        let tampered = SdJwt {
            jws: sd_jwt.jws.clone(),
            disclosures: vec![sd_jwt.disclosures[0].clone(), sd_jwt.disclosures[0].clone()],
            kb_jwt: None,
        };

        let result = verify(&tampered, &jwt_verifier, &hasher, &default_opts(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn verify_with_key_binding() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());
        let holder_key = b"holder-key-for-hmac-signing!!!";
        let holder_signer = HmacSha256Signer::new(holder_key);
        let holder_verifier = HmacSha256Verifier::new(holder_key);

        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();

        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "xyz789",
            signer: &holder_signer,
            iat: 1700000000,
        };

        let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some("https://verifier.example.com"),
            expected_nonce: Some("xyz789"),
        };

        let result = verify(
            &presentation,
            &jwt_verifier,
            &hasher,
            &opts,
            Some(&holder_verifier),
        )
        .unwrap();

        assert!(result.is_verified());
        assert_eq!(result.kb_verified, Some(true));
    }

    #[test]
    fn verify_kb_wrong_audience_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });
        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();
        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "xyz789",
            signer: &holder_signer,
            iat: 1700000000,
        };

        let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some("https://wrong-verifier.example.com"),
            expected_nonce: Some("xyz789"),
        };

        let result = verify(&presentation, &jwt_verifier, &hasher, &opts, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("aud mismatch"));
    }

    #[test]
    fn verify_kb_wrong_nonce_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });
        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();
        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "correct-nonce",
            signer: &holder_signer,
            iat: 1700000000,
        };

        let presentation = holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap();

        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some("https://verifier.example.com"),
            expected_nonce: Some("wrong-nonce"),
        };

        let result = verify(&presentation, &jwt_verifier, &hasher, &opts, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
    }

    #[test]
    fn verify_kb_required_but_missing_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let opts = VerificationOptions {
            verify_kb: true,
            ..Default::default()
        };
        let result = verify(&sd_jwt, &jwt_verifier, &hasher, &opts, None);
        assert!(result.is_err());
    }

    #[test]
    fn verify_sd_alg_mismatch_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        let wrong_hasher = crate::hasher::Sha384Hasher;
        let result = verify(&sd_jwt, &jwt_verifier, &wrong_hasher, &default_opts(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("_sd_alg mismatch"));
    }

    #[test]
    fn full_roundtrip_issue_present_verify() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());

        let claims = serde_json::json!({
            "iss": "https://issuer.example.com",
            "sub": "user123",
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com",
            "address": { "street": "123 Main St", "city": "Anytown", "state": "CA" }
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name", "email"],
            "address": { "_sd": ["street"] }
        });

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, None).unwrap();
        assert_eq!(sd_jwt.disclosures.len(), 4);

        let selected = holder::select_disclosures(&sd_jwt, &["given_name", "email"]);
        let presentation = holder::present(&sd_jwt, &selected, None, &hasher).unwrap();

        let serialized = presentation.serialize();
        let parsed = SdJwt::parse(&serialized, &hasher).unwrap();

        let result = verify(&parsed, &jwt_verifier, &hasher, &default_opts(), None).unwrap();

        assert!(result.is_verified());
        assert_eq!(result.claims["given_name"], "John");
        assert_eq!(result.claims["email"], "john@example.com");
        assert!(result.claims.get("family_name").is_none());
        assert_eq!(result.claims["address"]["city"], "Anytown");
        assert!(result.claims["address"].get("street").is_none());
    }
}
