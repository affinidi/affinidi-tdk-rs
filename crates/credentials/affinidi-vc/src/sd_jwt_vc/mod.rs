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
 * Reference: [draft-ietf-oauth-sd-jwt-vc](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
 */

use affinidi_sd_jwt::hasher::SdHasher;
use affinidi_sd_jwt::signer::JwtSigner;
use affinidi_sd_jwt::{SdJwt, issuer as sd_jwt_issuer};
use serde_json::Value;

pub mod error;

pub use error::SdJwtVcError;

/// An SD-JWT VC — an SD-JWT with enforced VC-specific claims.
///
/// Wraps `SdJwt` and ensures the payload contains the required claims:
/// `vct`, `iss`, `iat`, and optionally `exp`, `nbf`, `sub`, `status`, `cnf`.
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
    let mut full_claims = claims.as_object().cloned().unwrap_or_default();

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

/// Validate that the disclosure frame does not attempt to disclose protected claims.
///
/// Per SD-JWT VC spec, `vct`, `iss`, `iat`, `cnf`, and `exp` MUST NOT be
/// selectively disclosed — they must always be visible in the JWT payload.
fn validate_frame_no_protected_claims(frame: &Value) -> error::Result<()> {
    const PROTECTED_CLAIMS: &[&str] = &["vct", "iss", "iat", "exp", "nbf", "cnf"];

    if let Some(sd_array) = frame.get("_sd").and_then(|v| v.as_array()) {
        for item in sd_array {
            if let Some(name) = item.as_str()
                && PROTECTED_CLAIMS.contains(&name)
            {
                return Err(SdJwtVcError::InvalidVct(format!(
                    "\"{name}\" is a protected claim and must not be selectively disclosed"
                )));
            }
        }
    }

    Ok(())
}

/// Verify the temporal claims in an SD-JWT VC payload.
///
/// Checks `iat`, `exp`, and `nbf` against the current time.
pub fn verify_temporal(payload: &Value, now_unix: u64) -> error::Result<()> {
    // iat must be present
    let iat = payload
        .get("iat")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| SdJwtVcError::InvalidTemporal("iat is required".into()))?;

    // iat must not be in the future (with small tolerance)
    if iat > now_unix + 60 {
        return Err(SdJwtVcError::InvalidTemporal(format!(
            "iat ({iat}) is in the future"
        )));
    }

    // exp: if present, must be in the future
    if let Some(exp) = payload.get("exp").and_then(|v| v.as_u64())
        && now_unix > exp
    {
        return Err(SdJwtVcError::Expired);
    }

    // nbf: if present, must be in the past
    if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_u64())
        && now_unix < nbf
    {
        return Err(SdJwtVcError::NotYetValid);
    }

    Ok(())
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
