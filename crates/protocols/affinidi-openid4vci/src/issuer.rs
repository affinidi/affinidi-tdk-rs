/*!
 * Issuer-side OpenID4VCI operations.
 *
 * Handles credential issuance from the issuer's perspective:
 * - Credential offer generation
 * - Credential endpoint processing
 * - Proof of possession validation
 * - Token endpoint handling
 */

use serde_json::Value;

use crate::error::{Oid4vciError, Result};
use crate::types::*;

/// Validate a credential request from a wallet.
///
/// Checks:
/// - The format is supported
/// - Required fields are present
/// - Proof of possession (if present) has the right structure
pub fn validate_credential_request(request: &CredentialRequest) -> Result<()> {
    if request.format.is_empty() {
        return Err(Oid4vciError::InvalidRequest("format is required".into()));
    }

    // SD-JWT VC format requires vct
    if request.format == FORMAT_SD_JWT_VC && request.vct.is_none() {
        return Err(Oid4vciError::InvalidRequest(
            "vct is required for vc+sd-jwt format".into(),
        ));
    }

    // mdoc format requires doctype
    if request.format == FORMAT_MSO_MDOC && request.doctype.is_none() {
        return Err(Oid4vciError::InvalidRequest(
            "doctype is required for mso_mdoc format".into(),
        ));
    }

    // Validate proof if present
    if let Some(ref proof) = request.proof {
        if proof.proof_type.is_empty() {
            return Err(Oid4vciError::InvalidProof("proof_type is required".into()));
        }
        if proof.jwt.is_empty() {
            return Err(Oid4vciError::InvalidProof(
                "jwt is required in proof".into(),
            ));
        }
    }

    Ok(())
}

/// Create a credential response for a successful issuance.
pub fn create_credential_response(
    credential: Value,
    nonce: Option<String>,
    nonce_expires_in: Option<u64>,
) -> CredentialResponse {
    CredentialResponse {
        credential: Some(credential),
        transaction_id: None,
        c_nonce: nonce,
        c_nonce_expires_in: nonce_expires_in,
    }
}

/// Create a deferred credential response.
pub fn create_deferred_response(
    transaction_id: String,
    nonce: Option<String>,
) -> CredentialResponse {
    CredentialResponse {
        credential: None,
        transaction_id: Some(transaction_id),
        c_nonce: nonce,
        c_nonce_expires_in: None,
    }
}

/// Create a credential offer for initiating issuance.
///
/// The offer can be transmitted via QR code, deep link, or other out-of-band mechanism.
pub fn create_credential_offer(
    issuer_url: &str,
    credential_configuration_ids: Vec<String>,
    pre_authorized_code: Option<String>,
) -> CredentialOffer {
    let grants = if let Some(code) = pre_authorized_code {
        Some(Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: code,
                tx_code: None,
            }),
        })
    } else {
        Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant { issuer_state: None }),
            pre_authorized_code: None,
        })
    };

    CredentialOffer {
        credential_issuer: issuer_url.to_string(),
        credential_configuration_ids,
        grants,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sd_jwt_vc_request() {
        let req = CredentialRequest {
            format: FORMAT_SD_JWT_VC.to_string(),
            vct: Some("https://example.com/credentials/PID".into()),
            doctype: None,
            proof: Some(CredentialRequestProof {
                proof_type: "jwt".into(),
                jwt: "eyJ...".into(),
            }),
            credential_identifier: None,
        };

        assert!(validate_credential_request(&req).is_ok());
    }

    #[test]
    fn validate_sd_jwt_vc_missing_vct_fails() {
        let req = CredentialRequest {
            format: FORMAT_SD_JWT_VC.to_string(),
            vct: None,
            doctype: None,
            proof: None,
            credential_identifier: None,
        };

        assert!(validate_credential_request(&req).is_err());
    }

    #[test]
    fn validate_mdoc_missing_doctype_fails() {
        let req = CredentialRequest {
            format: FORMAT_MSO_MDOC.to_string(),
            vct: None,
            doctype: None,
            proof: None,
            credential_identifier: None,
        };

        assert!(validate_credential_request(&req).is_err());
    }

    #[test]
    fn create_offer_with_pre_auth() {
        let offer = create_credential_offer(
            "https://issuer.example.com",
            vec!["PID_SD_JWT".into()],
            Some("pre-auth-code-123".into()),
        );

        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert!(offer.grants.unwrap().pre_authorized_code.is_some());
    }

    #[test]
    fn create_offer_with_auth_code() {
        let offer =
            create_credential_offer("https://issuer.example.com", vec!["PID_MDOC".into()], None);

        assert!(offer.grants.unwrap().authorization_code.is_some());
    }

    #[test]
    fn create_response_with_credential() {
        let resp = create_credential_response(
            serde_json::json!("eyJ...sd-jwt..."),
            Some("nonce123".into()),
            Some(86400),
        );

        assert!(resp.credential.is_some());
        assert!(resp.transaction_id.is_none());
        assert_eq!(resp.c_nonce.as_deref(), Some("nonce123"));
    }

    #[test]
    fn create_deferred_response_test() {
        let resp = create_deferred_response("tx-123".into(), Some("nonce".into()));

        assert!(resp.credential.is_none());
        assert_eq!(resp.transaction_id.as_deref(), Some("tx-123"));
    }
}
