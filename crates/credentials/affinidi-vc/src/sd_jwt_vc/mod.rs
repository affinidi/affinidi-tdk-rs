/*!
 * SD-JWT-based Verifiable Credentials (SD-JWT VC).
 *
 * Implements the VC profile on top of SD-JWT (RFC 9901), adding:
 * - `vct` — Verifiable Credential Type identifier
 * - `iss` — Issuer identifier (HTTPS URL or DID)
 * - `iat`, `exp`, `nbf` — Temporal claims
 * - `sub` — Subject identifier
 * - `status` — Credential status for revocation/suspension
 * - `cnf` — Confirmation key for holder binding
 *
 * [`issue`] makes an SD-JWT VC. [`verify`] checks a received one: the issuer
 * signature and disclosures, key binding when requested, `vct` and `iss`, and
 * the temporal claims. It returns the `status` claim without checking it.
 *
 * Reference: [draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
 */

use affinidi_sd_jwt::hasher::SdHasher;
use affinidi_sd_jwt::signer::{JwtSigner, JwtVerifier};
use affinidi_sd_jwt::verifier::{self as sd_jwt_verifier, KeyBindingCheck, VerificationOptions};
use affinidi_sd_jwt::{SdJwt, issuer as sd_jwt_issuer};
use serde_json::Value;

pub mod error;

pub use error::SdJwtVcError;

/// An SD-JWT VC: an SD-JWT carrying the VC-specific claims `vct`, `iss` and
/// `iat`, and optionally `exp`, `nbf`, `sub`, `status` and `cnf`.
///
/// [`issue`] produces one with those claims in place. Holding an `SdJwtVc`
/// says nothing about whether it verifies: any `SdJwt` can be wrapped. Use
/// [`verify`] on a received SD-JWT VC.
#[derive(Debug, Clone)]
pub struct SdJwtVc {
    /// The underlying SD-JWT.
    pub sd_jwt: SdJwt,
}

impl SdJwtVc {
    /// Access the underlying SD-JWT.
    pub fn inner(&self) -> &SdJwt {
        &self.sd_jwt
    }

    /// Serialize the SD-JWT VC to the compact format.
    pub fn serialize(&self) -> String {
        self.sd_jwt.serialize()
    }

    /// Decode the JWT payload without verifying the signature.
    pub fn payload(&self) -> error::Result<Value> {
        Ok(self.sd_jwt.payload()?)
    }
}

impl std::fmt::Display for SdJwtVc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

/// Issue an SD-JWT VC.
///
/// # Arguments
///
/// * `vct` — Verifiable Credential Type (URN or HTTPS URL identifying the credential type)
/// * `issuer` — Issuer identifier (HTTPS URL or DID)
/// * `subject` — Optional subject identifier
/// * `claims` — The credential claims (will be merged with VC-specific claims)
/// * `disclosure_frame` — Which claims are selectively disclosable
/// * `signer` — Signs the JWT
/// * `hasher` — Hash function for disclosure digests
/// * `holder_jwk` — Optional holder public key for key binding
/// * `iat` — Issued-at timestamp (Unix seconds)
/// * `exp` — Optional expiration timestamp (Unix seconds)
///
/// # Required Claims (always in JWT payload, never selectively disclosed)
///
/// Per the SD-JWT VC spec, these claims MUST NOT be selectively disclosed:
/// - `vct` — credential type
/// - `iss` — issuer
/// - `iat` — issued at
/// - `cnf` — confirmation key (if present)
#[allow(clippy::too_many_arguments)]
pub fn issue(
    vct: &str,
    issuer: &str,
    subject: Option<&str>,
    claims: &Value,
    disclosure_frame: &Value,
    signer: &dyn JwtSigner,
    hasher: &dyn SdHasher,
    holder_jwk: Option<&Value>,
    iat: u64,
    exp: Option<u64>,
) -> error::Result<SdJwtVc> {
    if vct.is_empty() {
        return Err(SdJwtVcError::InvalidVct("vct must not be empty".into()));
    }
    if issuer.is_empty() {
        return Err(SdJwtVcError::InvalidIssuer(
            "issuer must not be empty".into(),
        ));
    }

    // Build the full claims object by merging VC-specific claims with user claims
    let mut full_claims = claims
        .as_object()
        .cloned()
        .ok_or_else(|| SdJwtVcError::InvalidClaims("claims must be a JSON object".into()))?;

    // Required VC claims (never selectively disclosed)
    full_claims.insert("vct".to_string(), Value::String(vct.to_string()));
    full_claims.insert("iss".to_string(), Value::String(issuer.to_string()));
    full_claims.insert("iat".to_string(), serde_json::json!(iat));

    if let Some(sub) = subject {
        full_claims.insert("sub".to_string(), Value::String(sub.to_string()));
    }

    if let Some(e) = exp {
        full_claims.insert("exp".to_string(), serde_json::json!(e));
    }

    let full_claims_value = Value::Object(full_claims);

    // Validate the disclosure frame doesn't try to disclose protected claims
    validate_frame_no_protected_claims(disclosure_frame)?;

    let sd_jwt = sd_jwt_issuer::issue(
        &full_claims_value,
        disclosure_frame,
        signer,
        hasher,
        holder_jwk,
    )?;

    Ok(SdJwtVc { sd_jwt })
}

/// Claims the SD-JWT VC profile keeps in the issuer-signed payload: they are
/// never selectively disclosable (draft-ietf-oauth-sd-jwt-vc §3.2.2). `iat`
/// is kept there too, as [`issue`] always writes it.
pub const PROTECTED_CLAIMS: &[&str] = &[
    "vct",
    "vct#integrity",
    "iss",
    "iat",
    "exp",
    "nbf",
    "cnf",
    "status",
];

/// Validate that the disclosure frame does not attempt to disclose protected claims.
fn validate_frame_no_protected_claims(frame: &Value) -> error::Result<()> {
    if let Some(sd_array) = frame.get("_sd").and_then(|v| v.as_array()) {
        for item in sd_array {
            if let Some(name) = item.as_str()
                && PROTECTED_CLAIMS.contains(&name)
            {
                return Err(SdJwtVcError::ProtectedClaim(format!(
                    "\"{name}\" is a protected claim and must not be selectively disclosed"
                )));
            }
        }
    }

    Ok(())
}

/// The leeway [`verify_temporal`] allows on `iat`.
pub const IAT_LEEWAY_SECS: u64 = 60;

/// Verify the temporal claims in an SD-JWT VC payload.
///
/// `iat` is required and may be up to [`IAT_LEEWAY_SECS`] ahead of `now_unix`.
/// `exp` and `nbf` are optional and checked with no leeway: the credential is
/// expired from the instant `now_unix == exp` (RFC 7519 §4.1.4). Each claim
/// that is present must be a non-negative integer, or the check fails.
pub fn verify_temporal(payload: &Value, now_unix: u64) -> error::Result<()> {
    check_temporal(payload, now_unix, IAT_LEEWAY_SECS, 0)
}

/// [`verify_temporal`] with one `leeway_secs` for clock skew on all three
/// claims: `iat` may be up to `leeway_secs` ahead, `exp` is honoured until
/// `leeway_secs` after it, and `nbf` from `leeway_secs` before it.
pub fn verify_temporal_with_leeway(
    payload: &Value,
    now_unix: u64,
    leeway_secs: u64,
) -> error::Result<()> {
    check_temporal(payload, now_unix, leeway_secs, leeway_secs)
}

fn check_temporal(
    payload: &Value,
    now_unix: u64,
    iat_leeway_secs: u64,
    leeway_secs: u64,
) -> error::Result<()> {
    let iat = numeric_date(payload, "iat")?
        .ok_or_else(|| SdJwtVcError::InvalidTemporal("iat is required".into()))?;
    if iat > now_unix.saturating_add(iat_leeway_secs) {
        return Err(SdJwtVcError::InvalidTemporal(format!(
            "iat ({iat}) is in the future"
        )));
    }

    if let Some(exp) = numeric_date(payload, "exp")?
        && now_unix >= exp.saturating_add(leeway_secs)
    {
        return Err(SdJwtVcError::Expired);
    }

    if let Some(nbf) = numeric_date(payload, "nbf")?
        && now_unix.saturating_add(leeway_secs) < nbf
    {
        return Err(SdJwtVcError::NotYetValid);
    }

    Ok(())
}

/// A NumericDate claim: `None` when absent, an error when present but not a
/// non-negative integer (a string, a fraction, a negative number, `null`).
fn numeric_date(payload: &Value, name: &str) -> error::Result<Option<u64>> {
    match payload.get(name) {
        None => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            SdJwtVcError::InvalidTemporal(format!(
                "{name} must be a non-negative integer, got {value}"
            ))
        }),
    }
}

/// What [`verify`] requires of an SD-JWT VC.
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions<'a> {
    /// The verifier's current time, seconds since the epoch.
    pub now: u64,
    /// Clock skew allowed on `iat`, `exp` and `nbf`
    /// ([`verify_temporal_with_leeway`]).
    pub leeway_secs: u64,
    /// `Some`: `vct` must equal it.
    pub expected_vct: Option<&'a str>,
    /// `Some`: `iss` must equal it.
    pub expected_issuer: Option<&'a str>,
    /// `Some`: a Key Binding JWT is required and checked under the
    /// credential's `cnf.jwk`. `None`: no key binding, and an SD-JWT VC that
    /// carries a KB-JWT is refused rather than accepted unchecked.
    pub key_binding: Option<KeyBindingCheck<'a>>,
}

/// An SD-JWT VC that [`verify`] accepted.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VerifiedSdJwtVc {
    /// The claims with the presented disclosures resolved.
    pub claims: Value,
    /// The `vct` claim.
    pub vct: String,
    /// The `iss` claim.
    pub issuer: String,
    /// The `status` claim, if any. [`verify`] does not fetch or check a
    /// status list: a caller that relies on revocation checks this reference
    /// itself (e.g. with `affinidi-status-list`).
    pub status: Option<Value>,
    /// Whether a KB-JWT was checked under `cnf.jwk` (always true when
    /// [`VerifyOptions::key_binding`] was given).
    pub key_bound: bool,
}

/// Verify a serialized SD-JWT VC (or a presentation of one).
///
/// In order:
/// 1. parse it, and verify it as an SD-JWT with `issuer_verifier` and
///    `hasher`, including the KB-JWT when `options.key_binding` is given (see
///    [`affinidi_sd_jwt::verifier::verify`]);
/// 2. refuse a KB-JWT that no key binding check was asked for;
/// 3. refuse a protected claim ([`PROTECTED_CLAIMS`]) that is not in the
///    issuer-signed payload itself;
/// 4. require a non-empty string `vct` and `iss`, equal to the expected ones
///    when given;
/// 5. check `iat`, `exp` and `nbf` ([`verify_temporal_with_leeway`]).
///
/// The `status` claim is returned, not checked.
pub fn verify(
    serialized: &str,
    issuer_verifier: &dyn JwtVerifier,
    hasher: &dyn SdHasher,
    options: &VerifyOptions,
) -> error::Result<VerifiedSdJwtVc> {
    let sd_jwt = SdJwt::parse(serialized, hasher)?;
    let sd_options = VerificationOptions {
        key_binding: options.key_binding,
    };
    let result = sd_jwt_verifier::verify(&sd_jwt, issuer_verifier, hasher, &sd_options)?;
    if !result.is_verified() {
        return Err(SdJwtVcError::Verification(
            "the SD-JWT VC carries a Key Binding JWT but no key binding check was requested".into(),
        ));
    }

    // The JWS whose signature was just verified.
    let payload = sd_jwt.payload()?;
    for name in PROTECTED_CLAIMS {
        if result.claims.get(*name) != payload.get(*name) {
            return Err(SdJwtVcError::ProtectedClaim(format!(
                "\"{name}\" must be in the issuer-signed payload, not a disclosure"
            )));
        }
    }

    let vct = required_string(&payload, "vct").map_err(SdJwtVcError::InvalidVct)?;
    if let Some(expected) = options.expected_vct
        && vct != expected
    {
        return Err(SdJwtVcError::InvalidVct(format!(
            "expected {expected}, got {vct}"
        )));
    }
    let issuer = required_string(&payload, "iss").map_err(SdJwtVcError::InvalidIssuer)?;
    if let Some(expected) = options.expected_issuer
        && issuer != expected
    {
        return Err(SdJwtVcError::InvalidIssuer(format!(
            "expected {expected}, got {issuer}"
        )));
    }

    verify_temporal_with_leeway(&payload, options.now, options.leeway_secs)?;

    Ok(VerifiedSdJwtVc {
        status: payload.get("status").cloned(),
        claims: result.claims,
        vct,
        issuer,
        key_bound: result.kb_verified == Some(true),
    })
}

fn required_string(payload: &Value, name: &str) -> Result<String, String> {
    match payload.get(name).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err(format!("{name} must be a non-empty string")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::signer::test_utils::HmacSha256Signer;

    fn test_signer() -> HmacSha256Signer {
        HmacSha256Signer::new(b"sd-jwt-vc-test-key-32-bytes-ok!")
    }

    #[test]
    fn issue_basic_sd_jwt_vc() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({
            "given_name": "John",
            "family_name": "Doe",
            "email": "john@example.com"
        });

        let frame = serde_json::json!({
            "_sd": ["given_name", "family_name", "email"]
        });

        let vc = issue(
            "https://example.com/credentials/IdentityCredential",
            "https://issuer.example.com",
            Some("did:example:subject"),
            &claims,
            &frame,
            &signer,
            &hasher,
            None,
            1700000000,
            Some(1800000000),
        )
        .unwrap();

        let payload = vc.payload().unwrap();

        // Protected claims must be visible
        assert_eq!(
            payload["vct"],
            "https://example.com/credentials/IdentityCredential"
        );
        assert_eq!(payload["iss"], "https://issuer.example.com");
        assert_eq!(payload["sub"], "did:example:subject");
        assert_eq!(payload["iat"], 1700000000);
        assert_eq!(payload["exp"], 1800000000);

        // Selectively disclosed claims must NOT be visible
        assert!(payload.get("given_name").is_none());
        assert!(payload.get("family_name").is_none());
        assert!(payload.get("email").is_none());

        // Must have disclosures
        assert_eq!(vc.sd_jwt.disclosures.len(), 3);
    }

    #[test]
    fn issue_with_holder_binding() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let holder_jwk = serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
            "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"
        });

        let claims = serde_json::json!({ "name": "Alice" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let vc = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &claims,
            &frame,
            &signer,
            &hasher,
            Some(&holder_jwk),
            1700000000,
            None,
        )
        .unwrap();

        let payload = vc.payload().unwrap();
        assert_eq!(payload["cnf"]["jwk"]["kty"], "EC");
    }

    #[test]
    fn reject_empty_vct() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let result = issue(
            "",
            "https://issuer.example.com",
            None,
            &serde_json::json!({}),
            &serde_json::json!({}),
            &signer,
            &hasher,
            None,
            1700000000,
            None,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("vct"));
    }

    #[test]
    fn reject_empty_issuer() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let result = issue(
            "IdentityCredential",
            "",
            None,
            &serde_json::json!({}),
            &serde_json::json!({}),
            &signer,
            &hasher,
            None,
            1700000000,
            None,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("issuer"));
    }

    #[test]
    fn reject_disclosing_protected_claims() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "name": "Alice" });

        // Try to disclose 'iss' — should fail
        let frame = serde_json::json!({ "_sd": ["iss", "name"] });
        let result = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &claims,
            &frame,
            &signer,
            &hasher,
            None,
            1700000000,
            None,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("protected"));

        // Try to disclose 'vct' — should fail
        let frame = serde_json::json!({ "_sd": ["vct"] });
        let result = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &claims,
            &frame,
            &signer,
            &hasher,
            None,
            1700000000,
            None,
        );

        assert!(result.is_err());
    }

    #[test]
    fn verify_temporal_valid() {
        let payload = serde_json::json!({
            "iat": 1700000000,
            "exp": 1800000000,
        });

        assert!(verify_temporal(&payload, 1750000000).is_ok());
    }

    #[test]
    fn verify_temporal_expired() {
        let payload = serde_json::json!({
            "iat": 1700000000,
            "exp": 1701000000,
        });

        assert!(matches!(
            verify_temporal(&payload, 1702000000),
            Err(SdJwtVcError::Expired)
        ));
    }

    #[test]
    fn verify_temporal_not_yet_valid() {
        let payload = serde_json::json!({
            "iat": 1700000000,
            "nbf": 1750000000,
        });

        assert!(matches!(
            verify_temporal(&payload, 1700000000),
            Err(SdJwtVcError::NotYetValid)
        ));
    }

    #[test]
    fn verify_temporal_missing_iat() {
        let payload = serde_json::json!({
            "exp": 1800000000,
        });

        assert!(verify_temporal(&payload, 1750000000).is_err());
    }

    #[test]
    fn verify_temporal_future_iat() {
        let payload = serde_json::json!({
            "iat": 1800000000,
        });

        // 1800000000 - 1700000000 = 100000000 >> 60 tolerance
        assert!(verify_temporal(&payload, 1700000000).is_err());
    }

    #[test]
    fn verify_temporal_refuses_a_malformed_exp_or_nbf() {
        for bad in [
            serde_json::json!("1700000000"),
            serde_json::json!(1_700_000_000.5),
            serde_json::json!(-1),
            serde_json::json!(i64::MIN),
            serde_json::Value::Null,
        ] {
            for name in ["exp", "nbf", "iat"] {
                let mut payload = serde_json::json!({ "iat": 1700000000 });
                payload[name] = bad.clone();
                assert!(
                    matches!(
                        verify_temporal(&payload, 1750000000),
                        Err(SdJwtVcError::InvalidTemporal(_))
                    ),
                    "{name} = {bad}"
                );
            }
        }
    }

    #[test]
    fn verify_temporal_expires_at_exp() {
        let payload = serde_json::json!({ "iat": 1700000000, "exp": 1750000000 });
        assert!(verify_temporal(&payload, 1749999999).is_ok());
        assert!(matches!(
            verify_temporal(&payload, 1750000000),
            Err(SdJwtVcError::Expired)
        ));
    }

    #[test]
    fn verify_temporal_is_valid_from_nbf() {
        let payload = serde_json::json!({ "iat": 1700000000, "nbf": 1750000000 });
        assert!(verify_temporal(&payload, 1750000000).is_ok());
        assert!(matches!(
            verify_temporal(&payload, 1749999999),
            Err(SdJwtVcError::NotYetValid)
        ));
    }

    #[test]
    fn verify_temporal_with_leeway_applies_to_every_claim() {
        let payload =
            serde_json::json!({ "iat": 1700000100, "exp": 1700000000, "nbf": 1700000130 });
        assert!(verify_temporal_with_leeway(&payload, 1700000029, 30).is_err());
        let ok = serde_json::json!({ "iat": 1700000030, "exp": 1700000000, "nbf": 1700000030 });
        assert!(verify_temporal_with_leeway(&ok, 1700000000, 30).is_ok());
        assert!(matches!(
            verify_temporal_with_leeway(&ok, 1700000030, 30),
            Err(SdJwtVcError::Expired)
        ));
    }

    #[test]
    fn verify_temporal_saturates_at_the_extremes() {
        let far = serde_json::json!({ "iat": u64::MAX, "exp": u64::MAX, "nbf": u64::MAX });
        assert!(verify_temporal_with_leeway(&far, u64::MAX - 1, 1).is_ok());
        assert!(matches!(
            verify_temporal_with_leeway(&far, u64::MAX, u64::MAX),
            Err(SdJwtVcError::Expired)
        ));
        assert!(verify_temporal(&far, 0).is_err());
        let epoch = serde_json::json!({ "iat": 0, "exp": 1 });
        assert!(verify_temporal(&epoch, 0).is_ok());
        assert!(matches!(
            verify_temporal(&epoch, u64::MAX),
            Err(SdJwtVcError::Expired)
        ));
    }

    #[test]
    fn issue_refuses_non_object_claims() {
        let result = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &serde_json::json!(["not", "an", "object"]),
            &serde_json::json!({}),
            &test_signer(),
            &Sha256Hasher,
            None,
            1700000000,
            None,
        );
        assert!(matches!(result, Err(SdJwtVcError::InvalidClaims(_))));
    }

    #[test]
    fn issue_refuses_a_disclosable_status() {
        let result = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &serde_json::json!({ "status": { "status_list": { "idx": 0, "uri": "https://example.com/sl" } } }),
            &serde_json::json!({ "_sd": ["status"] }),
            &test_signer(),
            &Sha256Hasher,
            None,
            1700000000,
            None,
        );
        assert!(matches!(result, Err(SdJwtVcError::ProtectedClaim(_))));
    }

    #[test]
    fn serialize_roundtrip() {
        let hasher = Sha256Hasher;
        let signer = test_signer();

        let claims = serde_json::json!({ "name": "Alice" });
        let frame = serde_json::json!({ "_sd": ["name"] });

        let vc = issue(
            "IdentityCredential",
            "https://issuer.example.com",
            None,
            &claims,
            &frame,
            &signer,
            &hasher,
            None,
            1700000000,
            None,
        )
        .unwrap();

        let serialized = vc.serialize();
        let parsed = SdJwt::parse(&serialized, &hasher).unwrap();
        assert_eq!(parsed.disclosures.len(), 1);
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use affinidi_sd_jwt::KbFreshness;
    use affinidi_sd_jwt::hasher::Sha256Hasher;
    use affinidi_sd_jwt::holder::{self, KbJwtInput};
    use affinidi_sd_jwt::signer::test_utils::{
        HmacSha256Signer, HmacSha256Verifier, hmac_verifier_from_jwk, oct_jwk,
    };

    const ISSUER_KEY: &[u8] = b"sd-jwt-vc-test-key-32-bytes-ok!";
    const HOLDER_KEY: &[u8] = b"sd-jwt-vc-holder-key-32-bytes!!";
    const VCT: &str = "https://example.com/IdentityCredential";
    const ISS: &str = "https://issuer.example.com";
    const AUD: &str = "https://verifier.example.com";
    const NONCE: &str = "n-1";
    const IAT: u64 = 1_700_000_000;

    fn issued(claims: Value, exp: Option<u64>) -> SdJwtVc {
        issue(
            VCT,
            ISS,
            Some("did:example:subject"),
            &claims,
            &serde_json::json!({ "_sd": ["given_name", "email"] }),
            &HmacSha256Signer::new(ISSUER_KEY),
            &Sha256Hasher,
            Some(&oct_jwk(HOLDER_KEY)),
            IAT,
            exp,
        )
        .unwrap()
    }

    fn identity() -> Value {
        serde_json::json!({ "given_name": "Alice", "email": "alice@example.com" })
    }

    fn presented(vc: &SdJwtVc) -> String {
        let signer = HmacSha256Signer::new(HOLDER_KEY);
        let reveal = holder::select_disclosures(&vc.sd_jwt, &["given_name"]);
        let kb = KbJwtInput {
            audience: AUD,
            nonce: NONCE,
            signer: &signer,
            iat: IAT,
        };
        holder::present(&vc.sd_jwt, &reveal, Some(&kb), &Sha256Hasher)
            .unwrap()
            .serialize()
    }

    fn options() -> VerifyOptions<'static> {
        VerifyOptions {
            now: IAT + 10,
            leeway_secs: 0,
            expected_vct: Some(VCT),
            expected_issuer: Some(ISS),
            key_binding: Some(KeyBindingCheck {
                audience: AUD,
                nonce: NONCE,
                freshness: KbFreshness::new(IAT as i64, 300),
                holder_key: &hmac_verifier_from_jwk,
            }),
        }
    }

    fn check(serialized: &str, options: &VerifyOptions) -> error::Result<VerifiedSdJwtVc> {
        verify(
            serialized,
            &HmacSha256Verifier::new(ISSUER_KEY),
            &Sha256Hasher,
            options,
        )
    }

    #[test]
    fn a_bound_presentation_verifies() {
        let mut claims = identity();
        claims["status"] =
            serde_json::json!({ "status_list": { "idx": 7, "uri": "https://example.com/sl" } });
        let verified = check(&presented(&issued(claims, Some(IAT + 3600))), &options()).unwrap();
        assert_eq!(verified.vct, VCT);
        assert_eq!(verified.issuer, ISS);
        assert!(verified.key_bound);
        assert_eq!(verified.claims["given_name"], "Alice");
        assert!(verified.claims.get("email").is_none());
        assert_eq!(verified.status.unwrap()["status_list"]["idx"], 7);
    }

    #[test]
    fn an_issued_credential_verifies_without_key_binding() {
        let vc = issued(identity(), None);
        let options = VerifyOptions {
            key_binding: None,
            ..options()
        };
        let verified = check(&vc.serialize(), &options).unwrap();
        assert!(!verified.key_bound);
        assert_eq!(verified.claims["email"], "alice@example.com");
    }

    #[test]
    fn a_kb_jwt_that_is_not_checked_is_refused() {
        let options = VerifyOptions {
            key_binding: None,
            ..options()
        };
        let err = check(&presented(&issued(identity(), None)), &options).unwrap_err();
        assert!(matches!(err, SdJwtVcError::Verification(_)), "{err}");
    }

    #[test]
    fn a_wrong_vct_or_issuer_is_refused() {
        let serialized = presented(&issued(identity(), None));
        let err = check(
            &serialized,
            &VerifyOptions {
                expected_vct: Some("https://example.com/Other"),
                ..options()
            },
        )
        .unwrap_err();
        assert!(matches!(err, SdJwtVcError::InvalidVct(_)), "{err}");
        let err = check(
            &serialized,
            &VerifyOptions {
                expected_issuer: Some("https://other.example.com"),
                ..options()
            },
        )
        .unwrap_err();
        assert!(matches!(err, SdJwtVcError::InvalidIssuer(_)), "{err}");
    }

    #[test]
    fn an_expired_credential_is_refused() {
        let serialized = presented(&issued(identity(), Some(IAT + 10)));
        let err = check(&serialized, &options()).unwrap_err();
        assert!(matches!(err, SdJwtVcError::Expired), "{err}");
    }

    #[test]
    fn a_malformed_exp_is_refused() {
        let mut claims = identity();
        claims["exp"] = serde_json::json!("1");
        let vc = SdJwtVc {
            sd_jwt: sd_jwt_issuer::issue(
                &{
                    let mut c = claims;
                    c["vct"] = VCT.into();
                    c["iss"] = ISS.into();
                    c["iat"] = IAT.into();
                    c
                },
                &serde_json::json!({}),
                &HmacSha256Signer::new(ISSUER_KEY),
                &Sha256Hasher,
                None,
            )
            .unwrap(),
        };
        let options = VerifyOptions {
            key_binding: None,
            ..options()
        };
        let err = check(&vc.serialize(), &options).unwrap_err();
        assert!(matches!(err, SdJwtVcError::InvalidTemporal(_)), "{err}");
    }

    /// An SD-JWT whose `exp` is a disclosure: withholding it would hide the
    /// expiry, so it is refused whether disclosed or not.
    #[test]
    fn a_protected_claim_from_a_disclosure_is_refused() {
        let claims = serde_json::json!({ "vct": VCT, "iss": ISS, "iat": IAT, "exp": IAT + 5 });
        let sd_jwt = sd_jwt_issuer::issue(
            &claims,
            &serde_json::json!({ "_sd": ["exp"] }),
            &HmacSha256Signer::new(ISSUER_KEY),
            &Sha256Hasher,
            None,
        )
        .unwrap();
        let options = VerifyOptions {
            key_binding: None,
            now: IAT + 10,
            ..options()
        };
        let err = check(&sd_jwt.serialize(), &options).unwrap_err();
        assert!(matches!(err, SdJwtVcError::ProtectedClaim(_)), "{err}");
    }

    #[test]
    fn a_credential_without_vct_or_iss_is_refused() {
        for (missing, claims) in [
            ("vct", serde_json::json!({ "iss": ISS, "iat": IAT })),
            ("iss", serde_json::json!({ "vct": VCT, "iat": IAT })),
        ] {
            let sd_jwt = sd_jwt_issuer::issue(
                &claims,
                &serde_json::json!({}),
                &HmacSha256Signer::new(ISSUER_KEY),
                &Sha256Hasher,
                None,
            )
            .unwrap();
            let options = VerifyOptions {
                key_binding: None,
                expected_vct: None,
                expected_issuer: None,
                ..options()
            };
            let err = check(&sd_jwt.serialize(), &options).unwrap_err();
            assert!(err.to_string().contains(missing), "{missing}: {err}");
        }
    }

    #[test]
    fn a_kb_jwt_under_another_key_is_refused() {
        let vc = issued(identity(), None);
        let signer = HmacSha256Signer::new(b"some-other-holder-key-32-bytes!");
        let kb = KbJwtInput {
            audience: AUD,
            nonce: NONCE,
            signer: &signer,
            iat: IAT,
        };
        let serialized = holder::present(&vc.sd_jwt, &[], Some(&kb), &Sha256Hasher)
            .unwrap()
            .serialize();
        let err = check(&serialized, &options()).unwrap_err();
        assert!(matches!(err, SdJwtVcError::SdJwt(_)), "{err}");
    }
}
