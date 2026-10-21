/*!
 * SD-JWT Verification: verify issuer signature, reconstruct claims,
 * and optionally verify Key Binding JWT.
 */

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
/// - A disclosure is not referenced from the payload, directly or through
///   another disclosure (RFC 9901 §7.1 step 5)
/// - A digest appears more than once, or a disclosure does not fit where its
///   digest sits (RFC 9901 §7.1 steps 3-4; see [`resolve_claims`])
/// - KB-JWT verification is requested but fails (missing cnf, sd_hash mismatch, etc.)
pub fn verify(
    sd_jwt: &SdJwt,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerificationOptions,
    holder_verifier: Option<&dyn JwtVerifier>,
) -> Result<VerificationResult> {
    verify_inner(
        sd_jwt,
        issuer_verifier,
        hasher,
        options,
        holder_verifier,
        None,
    )
}

/// How recent a Key Binding JWT's `iat` must be (RFC 9901 §7.3 step 5: the
/// verifier checks the creation time is within an acceptable window).
#[derive(Debug, Clone, Copy)]
pub struct KbFreshness {
    /// The verifier's current time, seconds since the epoch.
    pub now: i64,
    /// The oldest `iat` accepted, as seconds before `now`.
    pub max_age_secs: i64,
    /// How far ahead of `now` an `iat` may be, for clock skew.
    pub max_future_skew_secs: i64,
}

impl KbFreshness {
    /// A window of `max_age_secs` before `now`, allowing 60 seconds of skew
    /// ahead of it.
    pub fn new(now: i64, max_age_secs: i64) -> Self {
        Self {
            now,
            max_age_secs,
            max_future_skew_secs: 60,
        }
    }
}

/// [`verify`], and when the KB-JWT is verified, also require its `iat` within
/// `freshness`. A verifier that issues single-use nonces still wants this: a
/// nonce stops a replay, the window bounds how long a presentation built for
/// that nonce stays usable.
pub fn verify_with_kb_freshness(
    sd_jwt: &SdJwt,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerificationOptions,
    holder_verifier: Option<&dyn JwtVerifier>,
    freshness: &KbFreshness,
) -> Result<VerificationResult> {
    verify_inner(
        sd_jwt,
        issuer_verifier,
        hasher,
        options,
        holder_verifier,
        Some(freshness),
    )
}

fn verify_inner(
    sd_jwt: &SdJwt,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerificationOptions,
    holder_verifier: Option<&dyn JwtVerifier>,
    freshness: Option<&KbFreshness>,
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

    // 3. Each disclosure's digest is the one this hasher gives
    check_disclosure_digests(&sd_jwt.disclosures, hasher)?;

    // 4. Resolve disclosed claims (RFC 9901 §7.1 steps 3-5): every digest
    //    once, every disclosure referenced, recursively through disclosures
    let claims = resolve_claims(&payload, &sd_jwt.disclosures)?;

    // 5. Verify KB-JWT if requested
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

            // RFC 9901 §8.3: key binding only holds if the KB-JWT signature is
            // verified against the holder key the issuer committed to in
            // `cnf.jwk`. Decoding the KB-JWT *unverified* (the previous
            // fallback) lets anyone who obtains the SD-JWT mint a KB-JWT and
            // be reported as `kb_verified: true`. Callers MUST construct
            // `holder_verifier` from `cnf.jwk` above.
            let Some(hv) = holder_verifier else {
                return Err(SdJwtError::KeyBinding(
                    "holder_verifier required when verify_kb is true".into(),
                ));
            };
            let kb_payload = hv.verify_jwt(kb_jwt_str)?;

            // RFC 9901 §4.3 / §7.3: a KB-JWT's `typ` is `kb+jwt`. The header
            // was covered by the signature just verified; this keeps another
            // JWT the holder signed with the same key from passing as one.
            let typ = kb_jwt_typ(kb_jwt_str)?;
            if typ.as_deref() != Some(KB_JWT_TYP) {
                return Err(SdJwtError::KeyBinding(format!(
                    "KB-JWT typ must be {KB_JWT_TYP}, got {typ:?}"
                )));
            }

            if let Some(window) = freshness {
                let iat = kb_payload
                    .get("iat")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| SdJwtError::KeyBinding("iat missing in KB-JWT".into()))?;
                if iat > window.now + window.max_future_skew_secs {
                    return Err(SdJwtError::KeyBinding("KB-JWT iat is in the future".into()));
                }
                if window.now - iat > window.max_age_secs {
                    return Err(SdJwtError::KeyBinding(format!(
                        "KB-JWT is older than {}s",
                        window.max_age_secs
                    )));
                }
            }

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

/// The `typ` of a Key Binding JWT (RFC 9901 §4.3).
pub const KB_JWT_TYP: &str = "kb+jwt";

/// The `typ` header member of a compact JWS, if any.
fn kb_jwt_typ(jws: &str) -> Result<Option<String>> {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = jws
        .split('.')
        .next()
        .ok_or_else(|| SdJwtError::KeyBinding("KB-JWT is not a JWS".into()))?;
    let header: Value = URL_SAFE_NO_PAD
        .decode(header_b64)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| SdJwtError::KeyBinding("KB-JWT header is not JSON".into()))?;
    Ok(header
        .get("typ")
        .and_then(Value::as_str)
        .map(str::to_string))
}

/// Check each disclosure's digest against the verifying hasher, so a
/// disclosure parsed with another hash function cannot match by its old digest.
fn check_disclosure_digests(
    disclosures: &[crate::disclosure::Disclosure],
    hasher: &dyn SdHasher,
) -> Result<()> {
    for d in disclosures {
        let expected = hasher.hash_b64(d.serialized.as_bytes());
        if d.digest != expected {
            return Err(SdJwtError::Verification(format!(
                "disclosure digest not found in payload: {expected}"
            )));
        }
    }
    Ok(())
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
            expected_audience: Some("https://wrong-verifier.example.com"),
            expected_nonce: Some("xyz789"),
        };

        let result = verify(
            &presentation,
            &jwt_verifier,
            &hasher,
            &opts,
            Some(&holder_verifier),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("aud mismatch"));
    }

    #[test]
    fn verify_kb_wrong_nonce_fails() {
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

        let result = verify(
            &presentation,
            &jwt_verifier,
            &hasher,
            &opts,
            Some(&holder_verifier),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce mismatch"));
    }

    #[test]
    fn verify_kb_without_holder_verifier_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());
        let holder_signer = HmacSha256Signer::new(b"holder-key-for-hmac-signing!!!");

        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });
        let claims = serde_json::json!({ "sub": "user123" });
        let frame = serde_json::json!({});

        let sd_jwt = issuer::issue(&claims, &frame, &signer, &hasher, Some(&holder_jwk)).unwrap();
        let kb_input = KbJwtInput {
            audience: "https://verifier.example.com",
            nonce: "n",
            signer: &holder_signer,
            iat: 1700000000,
        };
        let presentation = holder::present(&sd_jwt, &[], Some(&kb_input), &hasher).unwrap();

        let opts = VerificationOptions {
            verify_kb: true,
            expected_audience: Some("https://verifier.example.com"),
            expected_nonce: Some("n"),
        };

        // No holder_verifier => must refuse rather than report kb_verified=true
        // on an unverified KB-JWT signature.
        let err = verify(&presentation, &jwt_verifier, &hasher, &opts, None).unwrap_err();
        assert!(matches!(err, SdJwtError::KeyBinding(_)), "got {err:?}");
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

#[cfg(test)]
mod kb_hardening_tests {
    use super::*;
    use crate::disclosure::Disclosure;
    use crate::hasher::Sha256Hasher;
    use crate::holder::{self, KbJwtInput};
    use crate::issuer;
    use crate::signer::JwtSigner;
    use crate::signer::test_utils::{HmacSha256Signer, HmacSha256Verifier};

    const ISSUER_KEY: &[u8] = b"test-secret-key-for-hmac-signing!";
    const HOLDER_KEY: &[u8] = b"holder-key-for-hmac-signing!!!";
    const AUD: &str = "decentralized_identifier:did:webvh:Qm1:verifier.example";

    fn opts() -> VerificationOptions<'static> {
        VerificationOptions {
            verify_kb: true,
            expected_audience: Some(AUD),
            expected_nonce: Some("n-1"),
        }
    }

    /// A presentation whose KB-JWT was made at `iat`.
    fn presented_at(iat: i64) -> SdJwt {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(ISSUER_KEY);
        let holder_signer = HmacSha256Signer::new(HOLDER_KEY);
        let holder_jwk = serde_json::json!({ "kty": "oct", "k": "holder-key" });
        let sd_jwt = issuer::issue(
            &serde_json::json!({ "sub": "u1", "name": "N" }),
            &serde_json::json!({ "_sd": ["name"] }),
            &signer,
            &hasher,
            Some(&holder_jwk),
        )
        .unwrap();
        let all: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        holder::present(
            &sd_jwt,
            &all,
            Some(&KbJwtInput {
                audience: AUD,
                nonce: "n-1",
                signer: &holder_signer,
                iat: iat as u64,
            }),
            &hasher,
        )
        .unwrap()
    }

    fn check(presentation: &SdJwt, now: i64) -> Result<VerificationResult> {
        verify_with_kb_freshness(
            presentation,
            &HmacSha256Verifier::new(ISSUER_KEY),
            &Sha256Hasher,
            &opts(),
            Some(&HmacSha256Verifier::new(HOLDER_KEY)),
            &KbFreshness::new(now, 300),
        )
    }

    #[test]
    fn a_fresh_kb_jwt_passes_and_a_stale_or_future_one_fails() {
        let now = 1_800_000_000;
        assert_eq!(
            check(&presented_at(now - 10), now).unwrap().kb_verified,
            Some(true)
        );
        let stale = check(&presented_at(now - 301), now).unwrap_err();
        assert!(stale.to_string().contains("older than"), "{stale}");
        let future = check(&presented_at(now + 120), now).unwrap_err();
        assert!(future.to_string().contains("future"), "{future}");
        // Plain `verify` keeps its behaviour: no window.
        verify(
            &presented_at(now - 10_000),
            &HmacSha256Verifier::new(ISSUER_KEY),
            &Sha256Hasher,
            &opts(),
            Some(&HmacSha256Verifier::new(HOLDER_KEY)),
        )
        .unwrap();
    }

    /// A JWT the holder signed with the same key, but not as a KB-JWT, does not
    /// pass as one even with every claim right.
    #[test]
    fn a_kb_jwt_without_the_kb_typ_is_refused() {
        let now = 1_800_000_000;
        let mut presentation = presented_at(now);
        let sd_hash = Sha256Hasher.hash_b64(presentation.serialize_without_kb().as_bytes());
        let holder_signer = HmacSha256Signer::new(HOLDER_KEY);
        presentation.kb_jwt = Some(
            holder_signer
                .sign_jwt(
                    &serde_json::json!({ "alg": holder_signer.algorithm(), "typ": "JWT" }),
                    &serde_json::json!({ "iat": now, "aud": AUD, "nonce": "n-1", "sd_hash": sd_hash }),
                )
                .unwrap(),
        );
        let err = check(&presentation, now).unwrap_err();
        assert!(err.to_string().contains("kb+jwt"), "{err}");
    }
}
