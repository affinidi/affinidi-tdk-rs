/*!
 * Shared types for OpenID4VCI.
 *
 * These types represent the protocol messages defined in the
 * OpenID4VCI 1.0 specification.
 */

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ── Issuer Metadata ─────────────────────────────────────────────────────────

/// Credential Issuer Metadata per OpenID4VCI §10.2.
///
/// Published at `/.well-known/openid-credential-issuer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialIssuerMetadata {
    /// The credential issuer identifier (HTTPS URL).
    pub credential_issuer: String,

    /// URL of the credential endpoint.
    pub credential_endpoint: String,

    /// URL of the batch credential endpoint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_credential_endpoint: Option<String>,

    /// URL of the deferred credential endpoint (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred_credential_endpoint: Option<String>,

    /// Supported credential configurations, keyed by credential_configuration_id.
    pub credential_configurations_supported: HashMap<String, CredentialConfiguration>,

    /// Display properties of the issuer (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayProperties>>,

    /// Additional metadata properties.
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// A supported credential configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialConfiguration {
    /// The credential format (e.g., "vc+sd-jwt", "mso_mdoc").
    pub format: String,

    /// The verifiable credential type (for SD-JWT VC: the `vct` value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// Document type for mdoc format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// Supported cryptographic binding methods (e.g., ["jwk"]).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cryptographic_binding_methods_supported: Option<Vec<String>>,

    /// Supported credential signing algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_signing_alg_values_supported: Option<Vec<String>>,

    /// Supported proof types for key binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_types_supported: Option<HashMap<String, ProofTypeMetadata>>,

    /// Claims that can be issued in this configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Value>,

    /// Display properties (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<DisplayProperties>>,

    /// Additional properties.
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// Metadata about a supported proof type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofTypeMetadata {
    /// Supported signing algorithms for the proof.
    pub proof_signing_alg_values_supported: Vec<String>,
}

/// Display properties for UI rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisplayProperties {
    /// Display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Locale (e.g., "en-US").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,

    /// Logo information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<LogoProperties>,

    /// Background color (CSS color string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,

    /// Text color (CSS color string).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
}

/// Logo properties for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoProperties {
    /// URI of the logo image.
    pub uri: String,

    /// Alt text for accessibility.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt_text: Option<String>,
}

// ── Credential Offer ────────────────────────────────────────────────────────

/// A credential offer initiating the issuance flow.
///
/// Transmitted via QR code, deep link, or other out-of-band mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialOffer {
    /// The credential issuer identifier.
    pub credential_issuer: String,

    /// IDs of offered credential configurations.
    pub credential_configuration_ids: Vec<String>,

    /// Pre-authorization grant (if using pre-auth code flow).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

/// OAuth 2.0 grant types for the credential offer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grants {
    /// Authorization code grant.
    #[serde(rename = "authorization_code", skip_serializing_if = "Option::is_none")]
    pub authorization_code: Option<AuthorizationCodeGrant>,

    /// Pre-authorized code grant.
    #[serde(
        rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        skip_serializing_if = "Option::is_none"
    )]
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
}

/// Authorization code grant parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCodeGrant {
    /// The issuer state to bind the offer to the authorization request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Pre-authorized code grant parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreAuthorizedCodeGrant {
    /// The pre-authorized code.
    #[serde(rename = "pre-authorized_code")]
    pub pre_authorized_code: String,

    /// Whether a user PIN is required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_code: Option<TxCodeConfig>,
}

/// Transaction code (PIN) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxCodeConfig {
    /// Input mode: "numeric" or "text".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_mode: Option<String>,

    /// Length of the expected code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length: Option<u32>,

    /// Description for the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// ── Credential Request/Response ─────────────────────────────────────────────

/// A credential request to the credential endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequest {
    /// The credential format requested.
    pub format: String,

    /// The VCT for SD-JWT VC format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,

    /// Document type for mdoc format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doctype: Option<String>,

    /// Proof of possession of the key material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<CredentialRequestProof>,

    /// Credential identifier for deferred issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_identifier: Option<String>,
}

/// Proof of possession in a credential request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialRequestProof {
    /// Proof type (e.g., "jwt").
    pub proof_type: String,

    /// The proof JWT.
    pub jwt: String,
}

/// A credential response from the credential endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialResponse {
    /// The issued credential (format depends on request).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential: Option<Value>,

    /// Transaction ID for deferred issuance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,

    /// Nonce for subsequent requests.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce: Option<String>,

    /// Nonce lifetime in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_nonce_expires_in: Option<u64>,
}

// ── Credential Format Constants ─────────────────────────────────────────────

/// SD-JWT VC credential format identifier.
pub const FORMAT_SD_JWT_VC: &str = "vc+sd-jwt";

/// ISO mdoc credential format identifier.
pub const FORMAT_MSO_MDOC: &str = "mso_mdoc";

/// JWT VC credential format identifier.
pub const FORMAT_JWT_VC_JSON: &str = "jwt_vc_json";

/// W3C LD VC credential format identifier.
pub const FORMAT_LDP_VC: &str = "ldp_vc";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_credential_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["IdentityCredential".to_string()],
            grants: Some(Grants {
                authorization_code: Some(AuthorizationCodeGrant {
                    issuer_state: Some("state123".to_string()),
                }),
                pre_authorized_code: None,
            }),
        };

        let json = serde_json::to_string_pretty(&offer).unwrap();
        assert!(json.contains("credential_issuer"));
        assert!(json.contains("IdentityCredential"));

        let parsed: CredentialOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.credential_issuer, "https://issuer.example.com");
    }

    #[test]
    fn serialize_pre_auth_offer() {
        let offer = CredentialOffer {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_configuration_ids: vec!["PID".to_string()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "SplxlOBeZQQYbYS6WxSbIA".to_string(),
                    tx_code: Some(TxCodeConfig {
                        input_mode: Some("numeric".to_string()),
                        length: Some(4),
                        description: Some("Enter the PIN sent to your phone".to_string()),
                    }),
                }),
            }),
        };

        let json = serde_json::to_string(&offer).unwrap();
        assert!(json.contains("pre-authorized_code"));
        assert!(json.contains("SplxlOBeZQQYbYS6WxSbIA"));

        let parsed: CredentialOffer = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed
                .grants
                .unwrap()
                .pre_authorized_code
                .unwrap()
                .pre_authorized_code,
            "SplxlOBeZQQYbYS6WxSbIA"
        );
    }

    #[test]
    fn serialize_credential_request() {
        let request = CredentialRequest {
            format: FORMAT_SD_JWT_VC.to_string(),
            vct: Some("https://example.com/credentials/PID".to_string()),
            doctype: None,
            proof: Some(CredentialRequestProof {
                proof_type: "jwt".to_string(),
                jwt: "eyJ...".to_string(),
            }),
            credential_identifier: None,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("vc+sd-jwt"));
        assert!(json.contains("jwt"));
    }

    #[test]
    fn serialize_credential_response() {
        let response = CredentialResponse {
            credential: Some(serde_json::json!("eyJhbGciOiJFUzI1NiJ9...")),
            transaction_id: None,
            c_nonce: Some("nonce123".to_string()),
            c_nonce_expires_in: Some(86400),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: CredentialResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.c_nonce.as_deref(), Some("nonce123"));
    }

    #[test]
    fn serialize_issuer_metadata() {
        let mut configs = HashMap::new();
        configs.insert(
            "PID_SD_JWT_VC".to_string(),
            CredentialConfiguration {
                format: FORMAT_SD_JWT_VC.to_string(),
                vct: Some("https://example.com/credentials/PID".to_string()),
                doctype: None,
                cryptographic_binding_methods_supported: Some(vec!["jwk".to_string()]),
                credential_signing_alg_values_supported: Some(vec![
                    "ES256".to_string(),
                    "EdDSA".to_string(),
                ]),
                proof_types_supported: None,
                claims: None,
                display: None,
                additional: HashMap::new(),
            },
        );

        let metadata = CredentialIssuerMetadata {
            credential_issuer: "https://issuer.example.com".to_string(),
            credential_endpoint: "https://issuer.example.com/credential".to_string(),
            batch_credential_endpoint: None,
            deferred_credential_endpoint: None,
            credential_configurations_supported: configs,
            display: None,
            additional: HashMap::new(),
        };

        let json = serde_json::to_string_pretty(&metadata).unwrap();
        assert!(json.contains("credential_issuer"));
        assert!(json.contains("PID_SD_JWT_VC"));
        assert!(json.contains("vc+sd-jwt"));

        let parsed: CredentialIssuerMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed.credential_configurations_supported["PID_SD_JWT_VC"].format,
            "vc+sd-jwt"
        );
    }
}
