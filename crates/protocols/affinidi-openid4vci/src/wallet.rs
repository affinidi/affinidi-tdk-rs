/*!
 * Wallet-side OpenID4VCI operations.
 *
 * Handles credential acquisition from the wallet's perspective:
 * - Issuer metadata discovery
 * - Credential offer parsing
 * - Proof of possession creation
 * - Credential request construction
 */

use crate::error::{Oid4vciError, Result};
use crate::types::*;

/// Parse a credential offer from a URI or JSON string.
///
/// Credential offers are received via QR code scan, deep link, or other
/// out-of-band mechanism. This function parses the JSON content.
pub fn parse_credential_offer(json: &str) -> Result<CredentialOffer> {
    serde_json::from_str(json).map_err(|e| Oid4vciError::InvalidOffer(e.to_string()))
}

/// Build a credential request for the SD-JWT VC format.
pub fn build_sd_jwt_vc_request(vct: &str, proof_jwt: Option<String>) -> CredentialRequest {
    CredentialRequest {
        format: FORMAT_SD_JWT_VC.to_string(),
        vct: Some(vct.to_string()),
        doctype: None,
        proof: proof_jwt.map(|jwt| CredentialRequestProof {
            proof_type: "jwt".to_string(),
            jwt,
        }),
        credential_identifier: None,
    }
}

/// Build a credential request for the ISO mdoc format.
pub fn build_mdoc_request(doctype: &str, proof_jwt: Option<String>) -> CredentialRequest {
    CredentialRequest {
        format: FORMAT_MSO_MDOC.to_string(),
        vct: None,
        doctype: Some(doctype.to_string()),
        proof: proof_jwt.map(|jwt| CredentialRequestProof {
            proof_type: "jwt".to_string(),
            jwt,
        }),
        credential_identifier: None,
    }
}

/// Construct the issuer metadata discovery URL.
///
/// Per OpenID4VCI §10.2: `{issuer_url}/.well-known/openid-credential-issuer`
pub fn metadata_url(issuer_url: &str) -> String {
    let base = issuer_url.trim_end_matches('/');
    format!("{base}/.well-known/openid-credential-issuer")
}

/// Extract the credential configuration for a specific format from metadata.
pub fn find_credential_config<'a>(
    metadata: &'a CredentialIssuerMetadata,
    format: &str,
) -> Option<(&'a String, &'a CredentialConfiguration)> {
    metadata
        .credential_configurations_supported
        .iter()
        .find(|(_, config)| config.format == format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_offer_json() {
        let json = serde_json::to_string(&json!({
            "credential_issuer": "https://issuer.example.com",
            "credential_configuration_ids": ["PID"],
            "grants": {
                "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                    "pre-authorized_code": "SplxlOBeZQQYbYS6WxSbIA"
                }
            }
        }))
        .unwrap();

        let offer = parse_credential_offer(&json).unwrap();
        assert_eq!(offer.credential_issuer, "https://issuer.example.com");
        assert_eq!(offer.credential_configuration_ids, vec!["PID"]);
    }

    #[test]
    fn build_sd_jwt_vc_req() {
        let req = build_sd_jwt_vc_request(
            "https://example.com/credentials/PID",
            Some("eyJ...proof-jwt".into()),
        );

        assert_eq!(req.format, FORMAT_SD_JWT_VC);
        assert_eq!(
            req.vct.as_deref(),
            Some("https://example.com/credentials/PID")
        );
        assert!(req.proof.is_some());
    }

    #[test]
    fn build_mdoc_req() {
        let req = build_mdoc_request("eu.europa.ec.eudi.pid.1", None);

        assert_eq!(req.format, FORMAT_MSO_MDOC);
        assert_eq!(req.doctype.as_deref(), Some("eu.europa.ec.eudi.pid.1"));
        assert!(req.proof.is_none());
    }

    #[test]
    fn metadata_url_construction() {
        assert_eq!(
            metadata_url("https://issuer.example.com"),
            "https://issuer.example.com/.well-known/openid-credential-issuer"
        );
        assert_eq!(
            metadata_url("https://issuer.example.com/"),
            "https://issuer.example.com/.well-known/openid-credential-issuer"
        );
    }
}
