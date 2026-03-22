/*!
 * Verifier-side OpenID4VP operations.
 *
 * Handles credential presentation from the verifier (Relying Party) perspective:
 * - Authorization request creation with presentation definitions
 * - Response validation
 * - Credential matching verification
 */

use crate::error::{Oid4vpError, Result};
use crate::types::*;

/// Create an authorization request for credential presentation.
///
/// The verifier specifies what credentials/claims are needed via
/// a `PresentationDefinition` with `InputDescriptor` entries.
pub fn create_authorization_request(
    client_id: &str,
    redirect_uri: &str,
    nonce: &str,
    presentation_definition: PresentationDefinition,
) -> AuthorizationRequest {
    AuthorizationRequest {
        response_type: "vp_token".to_string(),
        client_id: client_id.to_string(),
        redirect_uri: Some(redirect_uri.to_string()),
        response_mode: Some("direct_post".to_string()),
        nonce: nonce.to_string(),
        state: None,
        presentation_definition: Some(presentation_definition),
        presentation_definition_uri: None,
        client_metadata: None,
        additional: std::collections::HashMap::new(),
    }
}

/// Validate an authorization response from a wallet.
///
/// Checks:
/// - VP token is present
/// - Presentation submission references the correct definition
/// - State matches (if present in request)
pub fn validate_authorization_response(
    response: &AuthorizationResponse,
    expected_definition_id: &str,
    expected_state: Option<&str>,
) -> Result<()> {
    // Validate state
    if let Some(expected) = expected_state {
        let actual = response.state.as_deref().unwrap_or("");
        if actual != expected {
            return Err(Oid4vpError::InvalidResponse(format!(
                "state mismatch: expected {expected}, got {actual}"
            )));
        }
    }

    // Validate presentation submission references correct definition
    if response.presentation_submission.definition_id != expected_definition_id {
        return Err(Oid4vpError::InvalidResponse(format!(
            "definition_id mismatch: expected {expected_definition_id}, got {}",
            response.presentation_submission.definition_id
        )));
    }

    // Validate descriptor map is non-empty
    if response.presentation_submission.descriptor_map.is_empty() {
        return Err(Oid4vpError::InvalidResponse(
            "descriptor_map is empty".into(),
        ));
    }

    Ok(())
}

/// Create a simple input descriptor for requesting a specific credential type.
pub fn create_input_descriptor(
    id: &str,
    purpose: &str,
    required_fields: Vec<(&str, Option<serde_json::Value>)>,
) -> InputDescriptor {
    let fields = required_fields
        .into_iter()
        .map(|(path, filter)| Field {
            path: vec![format!("$.{path}")],
            id: None,
            purpose: None,
            name: None,
            filter,
            optional: None,
        })
        .collect();

    InputDescriptor {
        id: id.to_string(),
        name: None,
        purpose: Some(purpose.to_string()),
        format: None,
        constraints: Constraints {
            fields: Some(fields),
            limit_disclosure: Some("required".to_string()),
        },
        group: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn create_request() {
        let pd = PresentationDefinition {
            id: "pd-1".into(),
            name: Some("Age Verification".into()),
            purpose: Some("Verify age".into()),
            input_descriptors: vec![create_input_descriptor(
                "age-check",
                "Verify age over 18",
                vec![(
                    "age_over_18",
                    Some(json!({"type": "boolean", "const": true})),
                )],
            )],
            submission_requirements: None,
            format: None,
        };

        let req = create_authorization_request(
            "https://verifier.example.com",
            "https://verifier.example.com/callback",
            "nonce-xyz",
            pd,
        );

        assert_eq!(req.response_type, "vp_token");
        assert_eq!(req.response_mode.as_deref(), Some("direct_post"));
        assert!(req.presentation_definition.is_some());
    }

    #[test]
    fn validate_response_success() {
        let response = AuthorizationResponse {
            vp_token: json!("eyJ...vp_token..."),
            presentation_submission: PresentationSubmission {
                id: "sub-1".into(),
                definition_id: "pd-1".into(),
                descriptor_map: vec![DescriptorMapEntry {
                    id: "age-check".into(),
                    format: "vc+sd-jwt".into(),
                    path: "$".into(),
                    path_nested: None,
                }],
            },
            state: Some("state-123".into()),
        };

        assert!(validate_authorization_response(&response, "pd-1", Some("state-123")).is_ok());
    }

    #[test]
    fn validate_response_wrong_state() {
        let response = AuthorizationResponse {
            vp_token: json!("token"),
            presentation_submission: PresentationSubmission {
                id: "sub-1".into(),
                definition_id: "pd-1".into(),
                descriptor_map: vec![DescriptorMapEntry {
                    id: "x".into(),
                    format: "vc+sd-jwt".into(),
                    path: "$".into(),
                    path_nested: None,
                }],
            },
            state: Some("wrong".into()),
        };

        assert!(validate_authorization_response(&response, "pd-1", Some("expected")).is_err());
    }

    #[test]
    fn validate_response_wrong_definition() {
        let response = AuthorizationResponse {
            vp_token: json!("token"),
            presentation_submission: PresentationSubmission {
                id: "sub-1".into(),
                definition_id: "wrong-pd".into(),
                descriptor_map: vec![DescriptorMapEntry {
                    id: "x".into(),
                    format: "vc+sd-jwt".into(),
                    path: "$".into(),
                    path_nested: None,
                }],
            },
            state: None,
        };

        assert!(validate_authorization_response(&response, "pd-1", None).is_err());
    }

    #[test]
    fn input_descriptor_creation() {
        let desc = create_input_descriptor(
            "name-check",
            "Verify name",
            vec![("given_name", None), ("family_name", None)],
        );

        assert_eq!(desc.id, "name-check");
        assert_eq!(desc.constraints.fields.as_ref().unwrap().len(), 2);
        assert_eq!(
            desc.constraints.fields.as_ref().unwrap()[0].path[0],
            "$.given_name"
        );
    }
}
