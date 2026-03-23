/*!
 * Self-Issued OP Discovery Metadata per SIOPv2 §7.
 *
 * Published at `https://{issuer}/.well-known/openid-configuration`.
 */

use serde::{Deserialize, Serialize};

/// Self-Issued OP metadata per SIOPv2 §7.
///
/// Advertises the capabilities of the Self-Issued OP (wallet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiopMetadata {
    /// The authorization endpoint (custom scheme or app link).
    pub authorization_endpoint: String,

    /// The issuer identifier.
    pub issuer: String,

    /// Supported response types (MUST include "id_token").
    pub response_types_supported: Vec<String>,

    /// Supported scopes (MUST include "openid").
    pub scopes_supported: Vec<String>,

    /// Supported subject types ("pairwise" and/or "public").
    pub subject_types_supported: Vec<String>,

    /// Supported ID Token signing algorithms (e.g., "ES256", "EdDSA").
    pub id_token_signing_alg_values_supported: Vec<String>,

    /// Supported request object signing algorithms (MUST include "none").
    pub request_object_signing_alg_values_supported: Vec<String>,

    /// Supported subject syntax types.
    pub subject_syntax_types_supported: Vec<String>,

    /// Supported ID Token types (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token_types_supported: Option<Vec<String>>,
}

impl SiopMetadata {
    /// Create default metadata for a `siopv2://` scheme provider.
    pub fn siopv2_default() -> Self {
        Self {
            authorization_endpoint: "siopv2:".into(),
            issuer: "https://self-issued.me/v2".into(),
            response_types_supported: vec!["id_token".into()],
            scopes_supported: vec!["openid".into()],
            subject_types_supported: vec!["pairwise".into()],
            id_token_signing_alg_values_supported: vec!["ES256".into()],
            request_object_signing_alg_values_supported: vec!["none".into(), "ES256".into()],
            subject_syntax_types_supported: vec!["urn:ietf:params:oauth:jwk-thumbprint".into()],
            id_token_types_supported: Some(vec!["subject_signed_id_token".into()]),
        }
    }

    /// Create metadata that supports DID-based authentication.
    pub fn with_did_support(mut self, did_methods: Vec<String>) -> Self {
        self.subject_syntax_types_supported.extend(did_methods);
        self
    }

    /// Add EdDSA signing algorithm support.
    pub fn with_eddsa(mut self) -> Self {
        if !self
            .id_token_signing_alg_values_supported
            .contains(&"EdDSA".to_string())
        {
            self.id_token_signing_alg_values_supported
                .push("EdDSA".into());
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_metadata() {
        let meta = SiopMetadata::siopv2_default();
        assert!(
            meta.response_types_supported
                .contains(&"id_token".to_string())
        );
        assert!(meta.scopes_supported.contains(&"openid".to_string()));
        assert!(
            meta.subject_syntax_types_supported
                .contains(&"urn:ietf:params:oauth:jwk-thumbprint".to_string())
        );
    }

    #[test]
    fn metadata_with_did_support() {
        let meta = SiopMetadata::siopv2_default()
            .with_did_support(vec!["did:key".into(), "did:web".into(), "did:ebsi".into()])
            .with_eddsa();

        assert!(
            meta.subject_syntax_types_supported
                .contains(&"did:key".to_string())
        );
        assert!(
            meta.subject_syntax_types_supported
                .contains(&"did:ebsi".to_string())
        );
        assert!(
            meta.id_token_signing_alg_values_supported
                .contains(&"EdDSA".to_string())
        );
    }

    #[test]
    fn metadata_serialization() {
        let meta = SiopMetadata::siopv2_default();
        let json = serde_json::to_string_pretty(&meta).unwrap();
        assert!(json.contains("siopv2:"));
        assert!(json.contains("id_token"));

        let parsed: SiopMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.issuer, "https://self-issued.me/v2");
    }
}
