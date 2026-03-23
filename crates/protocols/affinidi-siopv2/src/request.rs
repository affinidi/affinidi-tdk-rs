/*!
 * SIOPv2 Authorization Request.
 *
 * The RP sends an authorization request to the Self-Issued OP (wallet)
 * via redirect URL, QR code, or deep link.
 */

use affinidi_oid4vc_core::{ClientMetadata, ResponseMode, ResponseType};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A SIOPv2 Authorization Request.
///
/// Sent by the RP to initiate authentication with the Self-Issued OP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// MUST be `id_token` for SIOPv2.
    pub response_type: ResponseType,

    /// The RP's client identifier (URL, DID, or pre-registered).
    pub client_id: String,

    /// Where to send the authorization response.
    pub redirect_uri: String,

    /// Nonce for replay protection. MUST be echoed in the ID Token.
    pub nonce: String,

    /// MUST include "openid".
    pub scope: String,

    /// Response mode (`fragment` for same-device, `direct_post` for cross-device).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<ResponseMode>,

    /// State parameter for session binding (echoed in response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// RP metadata inline.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<ClientMetadata>,

    /// RP metadata by reference (mutually exclusive with `client_metadata`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata_uri: Option<String>,

    /// Preferred ID Token type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_type: Option<String>,

    /// Signed request object (JWT per RFC 9101 / JAR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<String>,

    /// Request object by reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_uri: Option<String>,

    /// Additional parameters.
    #[serde(flatten)]
    pub additional: serde_json::Map<String, Value>,
}

impl AuthorizationRequest {
    /// Create a new SIOPv2 authorization request.
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            response_type: ResponseType::IdToken,
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            nonce: nonce.into(),
            scope: "openid".to_string(),
            response_mode: None,
            state: None,
            client_metadata: None,
            client_metadata_uri: None,
            id_token_type: None,
            request: None,
            request_uri: None,
            additional: serde_json::Map::new(),
        }
    }

    /// Set the response mode for cross-device flows.
    pub fn with_response_mode(mut self, mode: ResponseMode) -> Self {
        self.response_mode = Some(mode);
        self
    }

    /// Set the state parameter.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    /// Set inline client metadata.
    pub fn with_client_metadata(mut self, metadata: ClientMetadata) -> Self {
        self.client_metadata = Some(metadata);
        self.client_metadata_uri = None;
        self
    }

    /// Validate the request structure.
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.response_type != ResponseType::IdToken {
            return Err(crate::error::SiopError::InvalidRequest(
                "response_type must be id_token for SIOPv2".into(),
            ));
        }
        if !self.scope.contains("openid") {
            return Err(crate::error::SiopError::InvalidRequest(
                "scope must include openid".into(),
            ));
        }
        if self.nonce.is_empty() {
            return Err(crate::error::SiopError::InvalidRequest(
                "nonce is required".into(),
            ));
        }
        if self.client_metadata.is_some() && self.client_metadata_uri.is_some() {
            return Err(crate::error::SiopError::InvalidRequest(
                "client_metadata and client_metadata_uri are mutually exclusive".into(),
            ));
        }
        Ok(())
    }
}

/// A SIOPv2 Authorization Response.
///
/// Contains the Self-Issued ID Token (and optionally a VP Token).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The Self-Issued ID Token (JWT string).
    pub id_token: String,

    /// State echoed from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// VP Token (when combined with OpenID4VP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_token: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_basic_request() {
        let req = AuthorizationRequest::new(
            "https://rp.example.com",
            "https://rp.example.com/callback",
            "random-nonce-123",
        );

        assert_eq!(req.response_type, ResponseType::IdToken);
        assert_eq!(req.scope, "openid");
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_cross_device_request() {
        let req = AuthorizationRequest::new(
            "https://rp.example.com",
            "https://rp.example.com/callback",
            "nonce",
        )
        .with_response_mode(ResponseMode::DirectPost)
        .with_state("session-xyz");

        assert_eq!(req.response_mode, Some(ResponseMode::DirectPost));
        assert_eq!(req.state.as_deref(), Some("session-xyz"));
    }

    #[test]
    fn validate_empty_nonce_fails() {
        let req = AuthorizationRequest::new("rp", "redirect", "");
        assert!(req.validate().is_err());
    }

    #[test]
    fn serialize_request_roundtrip() {
        let req = AuthorizationRequest::new("rp", "redirect", "nonce").with_state("state");

        let json = serde_json::to_string(&req).unwrap();
        let parsed: AuthorizationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.client_id, "rp");
        assert_eq!(parsed.nonce, "nonce");
    }

    #[test]
    fn response_serialization() {
        let resp = AuthorizationResponse {
            id_token: "eyJ...".into(),
            state: Some("state123".into()),
            vp_token: None,
        };

        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("eyJ"));
        assert!(json.contains("state123"));
    }
}
