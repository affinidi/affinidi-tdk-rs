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

/// The hash algorithm an SD-JWT uses when its payload has no `_sd_alg`
/// (RFC 9901 §4.1.1).
pub const DEFAULT_SD_ALG: &str = "sha-256";

/// Builds the verifier for a Key Binding JWT from the holder key the issuer
/// put in the credential's `cnf.jwk` claim (RFC 9901 §4.1.2, §7.3).
///
/// [`verify`] calls it with the `jwk` member of `cnf` from the
/// **signature-verified** issuer payload, so the KB-JWT is always checked
/// against the key the issuer committed to. Implementations turn the JWK into
/// a verifier for that key, with the algorithm allowlist they accept, and
/// return an error for a key type they do not support.
///
/// Any `Fn(&Value) -> Result<Box<dyn JwtVerifier>>` closure implements it.
pub trait HolderKeyVerifier {
    /// A verifier for the KB-JWT signature under `jwk`.
    fn verifier_for_jwk(&self, jwk: &Value) -> Result<Box<dyn JwtVerifier>>;
}

impl<F> HolderKeyVerifier for F
where
    F: Fn(&Value) -> Result<Box<dyn JwtVerifier>>,
{
    fn verifier_for_jwk(&self, jwk: &Value) -> Result<Box<dyn JwtVerifier>> {
        self(jwk)
    }
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

    /// Whether `iat` falls in the window. A negative `iat` is refused, and the
    /// bounds saturate rather than wrap, so every `i64` gives an answer.
    fn check(&self, iat: i64) -> Result<()> {
        if iat < 0 {
            return Err(SdJwtError::KeyBinding("KB-JWT iat is negative".into()));
        }
        if iat > self.now.saturating_add(self.max_future_skew_secs) {
            return Err(SdJwtError::KeyBinding("KB-JWT iat is in the future".into()));
        }
        if self.now.saturating_sub(iat) > self.max_age_secs {
            return Err(SdJwtError::KeyBinding(format!(
                "KB-JWT is older than {}s",
                self.max_age_secs
            )));
        }
        Ok(())
    }
}

/// What a Key Binding JWT must show (RFC 9901 §7.3). Every member is required:
/// a KB-JWT is only bound to this presentation when its `aud`, `nonce` and
/// `iat` are checked and its signature verifies under the `cnf` key.
#[derive(Clone, Copy)]
pub struct KeyBindingCheck<'a> {
    /// The `aud` the KB-JWT must carry: this verifier. Must not be empty.
    pub audience: &'a str,
    /// The `nonce` the KB-JWT must carry: the one this verifier issued for
    /// the presentation. Must not be empty.
    pub nonce: &'a str,
    /// The window the KB-JWT's `iat` must fall in.
    pub freshness: KbFreshness,
    /// Turns the credential's `cnf.jwk` into the KB-JWT verifier.
    pub holder_key: &'a dyn HolderKeyVerifier,
}

impl std::fmt::Debug for KeyBindingCheck<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyBindingCheck")
            .field("audience", &self.audience)
            .field("nonce", &self.nonce)
            .field("freshness", &self.freshness)
            .finish_non_exhaustive()
    }
}

/// Options for SD-JWT verification.
#[derive(Debug, Default, Clone, Copy)]
pub struct VerificationOptions<'a> {
    /// `Some`: a Key Binding JWT is required and checked as described on
    /// [`KeyBindingCheck`]. `None`: key binding is not checked; a KB-JWT that
    /// is present is reported as `kb_verified: Some(false)`.
    pub key_binding: Option<KeyBindingCheck<'a>>,
}

impl<'a> VerificationOptions<'a> {
    /// Options that require and check a Key Binding JWT.
    pub fn with_key_binding(check: KeyBindingCheck<'a>) -> Self {
        Self {
            key_binding: Some(check),
        }
    }
}

/// Result of SD-JWT verification.
#[derive(Debug)]
pub struct VerificationResult {
    /// The fully resolved claims (with disclosed values restored).
    pub claims: Value,
    /// `Some(true)`: the KB-JWT was checked and verified. `Some(false)`: a
    /// KB-JWT is present but was not checked (no [`KeyBindingCheck`] given).
    /// `None`: no KB-JWT is present and none was required.
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
/// * `hasher` - The hash function: the payload's `_sd_alg`, or
///   [`DEFAULT_SD_ALG`] when it has none
/// * `options` - Whether a Key Binding JWT is required, and what it must show
///
/// # Errors
///
/// Returns an error if:
/// - The issuer JWS signature is invalid
/// - The hasher is not the payload's `_sd_alg` (or `sha-256` when absent)
/// - Duplicate disclosures are detected (RFC 9901 §8.1)
/// - A disclosure is not referenced from the payload, directly or through
///   another disclosure (RFC 9901 §7.1 step 5)
/// - A digest appears more than once, or a disclosure does not fit where its
///   digest sits (RFC 9901 §7.1 steps 3-4; see [`resolve_claims`])
/// - Key binding is required and the KB-JWT is missing, does not verify under
///   the payload's `cnf.jwk`, or has a wrong `typ`, `sd_hash`, `aud` or
///   `nonce`, or a missing or out-of-window `iat`
pub fn verify(
    sd_jwt: &SdJwt,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerificationOptions,
) -> Result<VerificationResult> {
    // 1. Verify the issuer JWS
    let payload = issuer_verifier.verify_jwt(&sd_jwt.jws)?;

    // 2. The hasher is the one the payload names, or the default when absent
    let sd_alg = match payload.get("_sd_alg") {
        None => DEFAULT_SD_ALG,
        Some(Value::String(alg)) => alg.as_str(),
        Some(_) => {
            return Err(SdJwtError::Verification("_sd_alg must be a string".into()));
        }
    };
    if sd_alg != hasher.alg_name() {
        return Err(SdJwtError::Verification(format!(
            "_sd_alg mismatch: expected {}, got {sd_alg}",
            hasher.alg_name()
        )));
    }

    // 3. Each disclosure's digest is the one this hasher gives
    check_disclosure_digests(&sd_jwt.disclosures, hasher)?;

    // 4. Resolve disclosed claims (RFC 9901 §7.1 steps 3-5): every digest
    //    once, every disclosure referenced, recursively through disclosures
    let claims = resolve_claims(&payload, &sd_jwt.disclosures)?;

    // 5. Verify the KB-JWT when key binding is required
    let kb_verified = match &options.key_binding {
        Some(check) => {
            verify_key_binding(sd_jwt, &payload, hasher, check)?;
            Some(true)
        }
        None => sd_jwt.kb_jwt.as_ref().map(|_| false),
    };

    Ok(VerificationResult {
        claims,
        kb_verified,
    })
}

/// RFC 9901 §7.3: the KB-JWT verifies under the issuer-signed `cnf.jwk`, is
/// typed `kb+jwt`, was made in the freshness window, and names this
/// presentation (`sd_hash`), this verifier (`aud`) and this request (`nonce`).
fn verify_key_binding(
    sd_jwt: &SdJwt,
    payload: &Value,
    hasher: &dyn SdHasher,
    check: &KeyBindingCheck,
) -> Result<()> {
    if check.audience.is_empty() {
        return Err(SdJwtError::KeyBinding(
            "key binding needs a non-empty expected audience".into(),
        ));
    }
    if check.nonce.is_empty() {
        return Err(SdJwtError::KeyBinding(
            "key binding needs a non-empty expected nonce".into(),
        ));
    }
    let kb_jwt = sd_jwt.kb_jwt.as_deref().ok_or_else(|| {
        SdJwtError::KeyBinding("key binding verification requested but no KB-JWT present".into())
    })?;

    let cnf_jwk = payload
        .get("cnf")
        .and_then(|v| v.get("jwk"))
        .filter(|v| v.is_object())
        .ok_or_else(|| {
            SdJwtError::KeyBinding(
                "cnf.jwk required in payload for key binding verification".into(),
            )
        })?;
    let holder_verifier = check.holder_key.verifier_for_jwk(cnf_jwk)?;
    let kb_payload = holder_verifier.verify_jwt(kb_jwt)?;

    // RFC 9901 §4.3 / §7.3: a KB-JWT's `typ` is `kb+jwt`. The header was
    // covered by the signature just verified; this keeps another JWT the
    // holder signed with the same key from passing as one.
    let typ = kb_jwt_typ(kb_jwt)?;
    if typ.as_deref() != Some(KB_JWT_TYP) {
        return Err(SdJwtError::KeyBinding(format!(
            "KB-JWT typ must be {KB_JWT_TYP}, got {typ:?}"
        )));
    }

    let iat = kb_payload
        .get("iat")
        .and_then(Value::as_i64)
        .ok_or_else(|| SdJwtError::KeyBinding("iat missing or not an integer in KB-JWT".into()))?;
    check.freshness.check(iat)?;

    let expected_sd_hash = hasher.hash_b64(sd_jwt.serialize_without_kb().as_bytes());
    let actual_sd_hash = kb_payload
        .get("sd_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::KeyBinding("sd_hash missing in KB-JWT".into()))?;
    if actual_sd_hash != expected_sd_hash {
        return Err(SdJwtError::KeyBinding(format!(
            "sd_hash mismatch: expected {expected_sd_hash}, got {actual_sd_hash}"
        )));
    }

    let actual_aud = kb_payload
        .get("aud")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::KeyBinding("aud missing in KB-JWT".into()))?;
    if actual_aud != check.audience {
        return Err(SdJwtError::KeyBinding(format!(
            "aud mismatch: expected {}, got {actual_aud}",
            check.audience
        )));
    }

    let actual_nonce = kb_payload
        .get("nonce")
        .and_then(Value::as_str)
        .ok_or_else(|| SdJwtError::KeyBinding("nonce missing in KB-JWT".into()))?;
    if actual_nonce != check.nonce {
        return Err(SdJwtError::KeyBinding(format!(
            "nonce mismatch: expected {}, got {actual_nonce}",
            check.nonce
        )));
    }

    Ok(())
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
    use crate::signer::JwtSigner;
    use crate::signer::test_utils::{
        HmacSha256Signer, HmacSha256Verifier, hmac_verifier_from_jwk, oct_jwk,
    };

    const HOLDER_KEY: &[u8] = b"holder-key-for-hmac-signing!!!";
    const AUD: &str = "https://verifier.example.com";
    const NONCE: &str = "xyz789";
    const IAT: u64 = 1_700_000_000;

    fn test_key() -> &'static [u8] {
        b"test-key-for-hmac-256-signing!!"
    }

    fn default_opts() -> VerificationOptions<'static> {
        VerificationOptions::default()
    }

    fn kb_check<'a>(audience: &'a str, nonce: &'a str) -> KeyBindingCheck<'a> {
        KeyBindingCheck {
            audience,
            nonce,
            freshness: KbFreshness::new(IAT as i64, 300),
            holder_key: &hmac_verifier_from_jwk,
        }
    }

    /// A credential bound to `cnf_key`, presented with a KB-JWT signed by
    /// `kb_key` for `AUD` and `NONCE`.
    fn bound_presentation(cnf_key: &[u8], kb_key: &[u8]) -> SdJwt {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let claims = serde_json::json!({ "sub": "user123", "name": "John" });
        let frame = serde_json::json!({ "_sd": ["name"] });
        let sd_jwt =
            issuer::issue(&claims, &frame, &signer, &hasher, Some(&oct_jwk(cnf_key))).unwrap();
        let all_refs: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        let kb_signer = HmacSha256Signer::new(kb_key);
        let kb_input = KbJwtInput {
            audience: AUD,
            nonce: NONCE,
            signer: &kb_signer,
            iat: IAT,
        };
        holder::present(&sd_jwt, &all_refs, Some(&kb_input), &hasher).unwrap()
    }

    fn verify_bound(presentation: &SdJwt, check: KeyBindingCheck) -> Result<VerificationResult> {
        verify(
            presentation,
            &HmacSha256Verifier::new(test_key()),
            &Sha256Hasher,
            &VerificationOptions::with_key_binding(check),
        )
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
        let result = verify(&sd_jwt, &jwt_verifier, &hasher, &default_opts()).unwrap();

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

        let result = verify(&presentation, &jwt_verifier, &hasher, &default_opts()).unwrap();
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

        let result = verify(&presentation, &jwt_verifier, &hasher, &default_opts()).unwrap();
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
        let result = verify(&sd_jwt, &wrong_verifier, &hasher, &default_opts());
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

        let result = verify(&tampered, &jwt_verifier, &hasher, &default_opts());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn verify_with_key_binding() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let result = verify_bound(&presentation, kb_check(AUD, NONCE)).unwrap();
        assert!(result.is_verified());
        assert_eq!(result.kb_verified, Some(true));
    }

    #[test]
    fn verify_kb_wrong_audience_fails() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let err = verify_bound(
            &presentation,
            kb_check("https://wrong-verifier.example.com", NONCE),
        )
        .unwrap_err();
        assert!(err.to_string().contains("aud mismatch"), "{err}");
    }

    #[test]
    fn verify_kb_wrong_nonce_fails() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let err = verify_bound(&presentation, kb_check(AUD, "wrong-nonce")).unwrap_err();
        assert!(err.to_string().contains("nonce mismatch"), "{err}");
    }

    #[test]
    fn verify_kb_with_empty_expected_audience_or_nonce_fails() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let err = verify_bound(&presentation, kb_check("", NONCE)).unwrap_err();
        assert!(err.to_string().contains("expected audience"), "{err}");
        let err = verify_bound(&presentation, kb_check(AUD, "")).unwrap_err();
        assert!(err.to_string().contains("expected nonce"), "{err}");
    }

    /// The KB-JWT is signed by a key other than the one in `cnf.jwk`. The
    /// verifier comes from `cnf.jwk`, so the signature does not verify.
    #[test]
    fn verify_kb_signed_by_a_key_other_than_cnf_fails() {
        let presentation = bound_presentation(HOLDER_KEY, b"another-holder-key-for-signing!");
        let err = verify_bound(&presentation, kb_check(AUD, NONCE)).unwrap_err();
        assert!(err.to_string().contains("signature mismatch"), "{err}");
    }

    /// The holder key verifier is handed the issuer-signed `cnf.jwk`.
    #[test]
    fn verify_kb_passes_the_cnf_jwk_to_the_holder_key_verifier() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let seen = std::cell::RefCell::new(None);
        let recording = |jwk: &Value| {
            *seen.borrow_mut() = Some(jwk.clone());
            hmac_verifier_from_jwk(jwk)
        };
        let check = KeyBindingCheck {
            holder_key: &recording,
            ..kb_check(AUD, NONCE)
        };
        verify_bound(&presentation, check).unwrap();
        assert_eq!(seen.into_inner(), Some(oct_jwk(HOLDER_KEY)));
    }

    #[test]
    fn verify_kb_without_cnf_jwk_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let sd_jwt = issuer::issue(
            &serde_json::json!({ "sub": "user123" }),
            &serde_json::json!({}),
            &signer,
            &hasher,
            None,
        )
        .unwrap();
        let kb_signer = HmacSha256Signer::new(HOLDER_KEY);
        let kb_input = KbJwtInput {
            audience: AUD,
            nonce: NONCE,
            signer: &kb_signer,
            iat: IAT,
        };
        let presentation = holder::present(&sd_jwt, &[], Some(&kb_input), &hasher).unwrap();
        let err = verify_bound(&presentation, kb_check(AUD, NONCE)).unwrap_err();
        assert!(matches!(err, SdJwtError::KeyBinding(_)), "got {err:?}");
        assert!(err.to_string().contains("cnf.jwk"), "{err}");
    }

    #[test]
    fn verify_kb_required_but_missing_fails() {
        let hasher = Sha256Hasher;
        let signer = HmacSha256Signer::new(test_key());
        let sd_jwt = issuer::issue(
            &serde_json::json!({ "sub": "user123", "name": "John" }),
            &serde_json::json!({ "_sd": ["name"] }),
            &signer,
            &hasher,
            Some(&oct_jwk(HOLDER_KEY)),
        )
        .unwrap();
        let err = verify_bound(&sd_jwt, kb_check(AUD, NONCE)).unwrap_err();
        assert!(err.to_string().contains("no KB-JWT"), "{err}");
    }

    #[test]
    fn a_kb_jwt_that_is_not_checked_is_not_reported_verified() {
        let presentation = bound_presentation(HOLDER_KEY, HOLDER_KEY);
        let result = verify(
            &presentation,
            &HmacSha256Verifier::new(test_key()),
            &Sha256Hasher,
            &default_opts(),
        )
        .unwrap();
        assert_eq!(result.kb_verified, Some(false));
        assert!(!result.is_verified());
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
        let result = verify(&sd_jwt, &jwt_verifier, &wrong_hasher, &default_opts());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("_sd_alg mismatch"));
    }

    /// No `_sd_alg` means `sha-256`, so another hasher is refused up front.
    #[test]
    fn an_absent_sd_alg_is_sha_256() {
        let signer = HmacSha256Signer::new(test_key());
        let jwt_verifier = HmacSha256Verifier::new(test_key());
        let jws = signer
            .sign_jwt(
                &serde_json::json!({ "alg": "HS256", "typ": "sd+jwt" }),
                &serde_json::json!({ "sub": "user123" }),
            )
            .unwrap();
        let sd_jwt = SdJwt::new(jws, vec![], None);
        verify(&sd_jwt, &jwt_verifier, &Sha256Hasher, &default_opts()).unwrap();
        let err = verify(
            &sd_jwt,
            &jwt_verifier,
            &crate::hasher::Sha384Hasher,
            &default_opts(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("_sd_alg mismatch"), "{err}");
    }

    #[test]
    fn a_non_string_sd_alg_is_refused() {
        let signer = HmacSha256Signer::new(test_key());
        let jws = signer
            .sign_jwt(
                &serde_json::json!({ "alg": "HS256", "typ": "sd+jwt" }),
                &serde_json::json!({ "sub": "user123", "_sd_alg": 256 }),
            )
            .unwrap();
        let err = verify(
            &SdJwt::new(jws, vec![], None),
            &HmacSha256Verifier::new(test_key()),
            &Sha256Hasher,
            &default_opts(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("_sd_alg"), "{err}");
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

        let result = verify(&parsed, &jwt_verifier, &hasher, &default_opts()).unwrap();

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
    use crate::signer::test_utils::{
        HmacSha256Signer, HmacSha256Verifier, hmac_verifier_from_jwk, oct_jwk,
    };

    const ISSUER_KEY: &[u8] = b"test-secret-key-for-hmac-signing!";
    const HOLDER_KEY: &[u8] = b"holder-key-for-hmac-signing!!!";
    const AUD: &str = "decentralized_identifier:did:webvh:Qm1:verifier.example";

    fn issued() -> SdJwt {
        issuer::issue(
            &serde_json::json!({ "sub": "u1", "name": "N" }),
            &serde_json::json!({ "_sd": ["name"] }),
            &HmacSha256Signer::new(ISSUER_KEY),
            &Sha256Hasher,
            Some(&oct_jwk(HOLDER_KEY)),
        )
        .unwrap()
    }

    /// A presentation whose KB-JWT was made at `iat`.
    fn presented_at(iat: u64) -> SdJwt {
        let sd_jwt = issued();
        let holder_signer = HmacSha256Signer::new(HOLDER_KEY);
        let all: Vec<&Disclosure> = sd_jwt.disclosures.iter().collect();
        holder::present(
            &sd_jwt,
            &all,
            Some(&KbJwtInput {
                audience: AUD,
                nonce: "n-1",
                signer: &holder_signer,
                iat,
            }),
            &Sha256Hasher,
        )
        .unwrap()
    }

    /// A presentation whose KB-JWT carries `iat` exactly as given, signed by
    /// the holder with every other claim right.
    fn presented_with_iat(iat: serde_json::Value) -> SdJwt {
        let mut presentation = presented_at(0);
        let sd_hash = Sha256Hasher.hash_b64(presentation.serialize_without_kb().as_bytes());
        let mut claims = serde_json::json!({ "aud": AUD, "nonce": "n-1", "sd_hash": sd_hash });
        if !iat.is_null() {
            claims["iat"] = iat;
        }
        let holder_signer = HmacSha256Signer::new(HOLDER_KEY);
        presentation.kb_jwt = Some(
            holder_signer
                .sign_jwt(
                    &serde_json::json!({ "alg": holder_signer.algorithm(), "typ": KB_JWT_TYP }),
                    &claims,
                )
                .unwrap(),
        );
        presentation
    }

    fn check_with(presentation: &SdJwt, freshness: KbFreshness) -> Result<VerificationResult> {
        verify(
            presentation,
            &HmacSha256Verifier::new(ISSUER_KEY),
            &Sha256Hasher,
            &VerificationOptions::with_key_binding(KeyBindingCheck {
                audience: AUD,
                nonce: "n-1",
                freshness,
                holder_key: &hmac_verifier_from_jwk,
            }),
        )
    }

    fn check(presentation: &SdJwt, now: i64) -> Result<VerificationResult> {
        check_with(presentation, KbFreshness::new(now, 300))
    }

    #[test]
    fn a_fresh_kb_jwt_passes_and_a_stale_or_future_one_fails() {
        let now = 1_800_000_000;
        let at = |offset: i64| presented_at((now + offset) as u64);
        assert_eq!(check(&at(-10), now).unwrap().kb_verified, Some(true));
        let stale = check(&at(-301), now).unwrap_err();
        assert!(stale.to_string().contains("older than"), "{stale}");
        let future = check(&at(120), now).unwrap_err();
        assert!(future.to_string().contains("future"), "{future}");
    }

    #[test]
    fn the_window_edges_are_inclusive() {
        let now = 1_800_000_000;
        check(&presented_at((now - 300) as u64), now).unwrap();
        check(&presented_at((now + 60) as u64), now).unwrap();
        check(&presented_at((now + 61) as u64), now).unwrap_err();
    }

    /// RFC 9901 §4.3: `iat` is required in a KB-JWT.
    #[test]
    fn a_kb_jwt_without_an_integer_iat_is_refused() {
        let now = 1_800_000_000;
        for iat in [
            serde_json::Value::Null,
            serde_json::json!("1800000000"),
            serde_json::json!(1_800_000_000.5),
            serde_json::json!(u64::MAX),
        ] {
            let err = check(&presented_with_iat(iat.clone()), now).unwrap_err();
            assert!(err.to_string().contains("iat missing"), "{iat}: {err}");
        }
    }

    /// Extreme `iat` values give an answer rather than overflowing.
    #[test]
    fn extreme_iat_values_are_refused() {
        let now = 1_800_000_000;
        let err = check(&presented_with_iat(serde_json::json!(i64::MIN)), now).unwrap_err();
        assert!(err.to_string().contains("negative"), "{err}");
        let err = check(&presented_with_iat(serde_json::json!(-1)), now).unwrap_err();
        assert!(err.to_string().contains("negative"), "{err}");
        let err = check(&presented_with_iat(serde_json::json!(i64::MAX)), now).unwrap_err();
        assert!(err.to_string().contains("future"), "{err}");
    }

    /// Extreme window values saturate rather than overflow.
    #[test]
    fn extreme_window_values_do_not_overflow() {
        let presentation = presented_with_iat(serde_json::json!(0));
        let wide = KbFreshness {
            now: i64::MAX,
            max_age_secs: i64::MAX,
            max_future_skew_secs: i64::MAX,
        };
        check_with(&presentation, wide).unwrap();

        let from_min = KbFreshness {
            now: i64::MIN,
            max_age_secs: 300,
            max_future_skew_secs: 60,
        };
        let err = check_with(&presentation, from_min).unwrap_err();
        assert!(err.to_string().contains("future"), "{err}");

        let at_max = presented_with_iat(serde_json::json!(i64::MAX));
        let at_the_end_of_time = KbFreshness {
            now: i64::MAX,
            max_age_secs: 0,
            max_future_skew_secs: 0,
        };
        check_with(&at_max, at_the_end_of_time).unwrap();
    }

    /// A JWT the holder signed with the same key, but not as a KB-JWT, does not
    /// pass as one even with every claim right.
    #[test]
    fn a_kb_jwt_without_the_kb_typ_is_refused() {
        let now = 1_800_000_000;
        let mut presentation = presented_at(now as u64);
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
