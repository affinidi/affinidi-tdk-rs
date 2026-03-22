/*!
 * Shared types for OpenID4VP and Presentation Exchange v2.
 *
 * References:
 * - [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
 * - [Presentation Exchange v2](https://identity.foundation/presentation-exchange/spec/v2.0.0/)
 */

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

// ── Authorization Request ───────────────────────────────────────────────────

/// An OpenID4VP authorization request from a verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The response type (must be "vp_token").
    pub response_type: String,

    /// The client (verifier) identifier.
    pub client_id: String,

    /// Where to send the response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Response mode (e.g., "direct_post", "fragment").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mode: Option<String>,

    /// Nonce for replay protection.
    pub nonce: String,

    /// State parameter for session binding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,

    /// The presentation definition (what credentials/claims are requested).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition: Option<PresentationDefinition>,

    /// URI pointing to a hosted presentation definition.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presentation_definition_uri: Option<String>,

    /// Verifier metadata (optional, for wallet to validate the verifier).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_metadata: Option<Value>,

    /// Additional parameters.
    #[serde(flatten)]
    pub additional: HashMap<String, Value>,
}

/// An OpenID4VP authorization response from the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    /// The VP token (one or more verifiable presentations).
    pub vp_token: Value,

    /// The presentation submission describing which credentials match which descriptors.
    pub presentation_submission: PresentationSubmission,

    /// State echoed from the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

// ── Presentation Exchange v2 ────────────────────────────────────────────────

/// A Presentation Definition specifying what credentials the verifier requires.
///
/// Per Presentation Exchange v2.0.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationDefinition {
    /// Unique identifier for this definition.
    pub id: String,

    /// Optional human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// Input descriptors — each describes a required credential or claim.
    pub input_descriptors: Vec<InputDescriptor>,

    /// Submission requirements (complex matching logic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submission_requirements: Option<Vec<SubmissionRequirement>>,

    /// Format requirements (which credential formats are accepted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, FormatRequirement>>,
}

/// An Input Descriptor specifying a required credential or set of claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputDescriptor {
    /// Unique identifier for this descriptor.
    pub id: String,

    /// Optional human-readable name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Optional purpose description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// Format requirements specific to this descriptor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<HashMap<String, FormatRequirement>>,

    /// Constraints on the credential (JSON path filters).
    pub constraints: Constraints,

    /// Group membership for submission requirements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<Vec<String>>,
}

/// Constraints applied to an input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constraints {
    /// Required fields/claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,

    /// Whether the credential must be retained by the verifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_disclosure: Option<String>,
}

/// A field constraint — specifies a required claim via JSON path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Field {
    /// JSON paths to the required claim (JSONPath expressions).
    pub path: Vec<String>,

    /// Optional identifier for this field.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Optional purpose description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,

    /// Optional name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Filter on the claim value (JSON Schema).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Value>,

    /// Whether this field is optional.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Format requirement for a credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormatRequirement {
    /// Supported algorithms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Vec<String>>,

    /// Supported proof types.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<Vec<String>>,
}

/// Submission requirement for complex matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionRequirement {
    /// Rule: "all" or "pick".
    pub rule: String,

    /// For "pick": how many to select.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<usize>,

    /// For "pick": minimum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<usize>,

    /// For "pick": maximum.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<usize>,

    /// Group name to match against input descriptor groups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,

    /// Nested requirements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_nested: Option<Vec<SubmissionRequirement>>,
}

// ── Presentation Submission ─────────────────────────────────────────────────

/// A Presentation Submission mapping credentials to input descriptors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationSubmission {
    /// Unique identifier.
    pub id: String,

    /// ID of the presentation definition being fulfilled.
    pub definition_id: String,

    /// Descriptor map — which credential satisfies which input descriptor.
    pub descriptor_map: Vec<DescriptorMapEntry>,
}

/// Maps a credential to an input descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DescriptorMapEntry {
    /// The input descriptor ID being fulfilled.
    pub id: String,

    /// The credential format (e.g., "vc+sd-jwt", "mso_mdoc").
    pub format: String,

    /// JSON path to the credential in the VP token.
    pub path: String,

    /// Nested path for enveloped credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_nested: Option<Box<DescriptorMapEntry>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serialize_presentation_definition() {
        let pd = PresentationDefinition {
            id: "pd-1".to_string(),
            name: Some("Identity Verification".to_string()),
            purpose: Some("Verify your identity".to_string()),
            input_descriptors: vec![InputDescriptor {
                id: "id-1".to_string(),
                name: Some("PID".to_string()),
                purpose: Some("We need your name".to_string()),
                format: None,
                constraints: Constraints {
                    fields: Some(vec![
                        Field {
                            path: vec!["$.given_name".to_string()],
                            id: None,
                            purpose: None,
                            name: None,
                            filter: None,
                            optional: None,
                        },
                        Field {
                            path: vec!["$.family_name".to_string()],
                            id: None,
                            purpose: None,
                            name: None,
                            filter: None,
                            optional: None,
                        },
                    ]),
                    limit_disclosure: Some("required".to_string()),
                },
                group: None,
            }],
            submission_requirements: None,
            format: None,
        };

        let json = serde_json::to_string_pretty(&pd).unwrap();
        assert!(json.contains("input_descriptors"));
        assert!(json.contains("$.given_name"));

        let parsed: PresentationDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "pd-1");
        assert_eq!(parsed.input_descriptors.len(), 1);
    }

    #[test]
    fn serialize_authorization_request() {
        let request = AuthorizationRequest {
            response_type: "vp_token".to_string(),
            client_id: "https://verifier.example.com".to_string(),
            redirect_uri: Some("https://verifier.example.com/callback".to_string()),
            response_mode: Some("direct_post".to_string()),
            nonce: "n-0S6_WzA2Mj".to_string(),
            state: Some("state123".to_string()),
            presentation_definition: Some(PresentationDefinition {
                id: "pd-1".to_string(),
                name: None,
                purpose: None,
                input_descriptors: vec![],
                submission_requirements: None,
                format: None,
            }),
            presentation_definition_uri: None,
            client_metadata: None,
            additional: HashMap::new(),
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("vp_token"));
        assert!(json.contains("direct_post"));
    }

    #[test]
    fn serialize_authorization_response() {
        let response = AuthorizationResponse {
            vp_token: json!("eyJhbGciOiJFUzI1NiJ9..."),
            presentation_submission: PresentationSubmission {
                id: "sub-1".to_string(),
                definition_id: "pd-1".to_string(),
                descriptor_map: vec![DescriptorMapEntry {
                    id: "id-1".to_string(),
                    format: "vc+sd-jwt".to_string(),
                    path: "$".to_string(),
                    path_nested: None,
                }],
            },
            state: Some("state123".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        let parsed: AuthorizationResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.presentation_submission.descriptor_map.len(), 1);
        assert_eq!(
            parsed.presentation_submission.descriptor_map[0].format,
            "vc+sd-jwt"
        );
    }

    #[test]
    fn format_requirements() {
        let mut formats = HashMap::new();
        formats.insert(
            "vc+sd-jwt".to_string(),
            FormatRequirement {
                alg: Some(vec!["ES256".to_string(), "EdDSA".to_string()]),
                proof_type: None,
            },
        );

        let pd = PresentationDefinition {
            id: "pd-formats".to_string(),
            name: None,
            purpose: None,
            input_descriptors: vec![],
            submission_requirements: None,
            format: Some(formats),
        };

        let json = serde_json::to_string(&pd).unwrap();
        assert!(json.contains("ES256"));
        assert!(json.contains("EdDSA"));
    }

    #[test]
    fn field_with_filter() {
        let field = Field {
            path: vec!["$.age_over_18".to_string()],
            id: None,
            purpose: None,
            name: None,
            filter: Some(json!({ "type": "boolean", "const": true })),
            optional: None,
        };

        let json = serde_json::to_string(&field).unwrap();
        assert!(json.contains("age_over_18"));
        assert!(json.contains("boolean"));
    }
}
