/*!
 * Wallet-side OpenID4VP operations.
 *
 * Handles credential presentation from the wallet's perspective:
 * - Parse and validate authorization requests
 * - Match credentials against input descriptors
 * - Build VP token and presentation submission
 * - Send authorization response
 */

use crate::error::{Oid4vpError, Result};
use crate::types::*;
use serde_json::Value;

/// Parse an authorization request from a URI query string or JSON.
pub fn parse_authorization_request(json: &str) -> Result<AuthorizationRequest> {
    serde_json::from_str(json).map_err(|e| Oid4vpError::InvalidRequest(format!("parse error: {e}")))
}

/// Build a presentation submission for matching credentials.
///
/// Each entry in `matches` maps an input descriptor ID to a credential format and path.
pub fn build_presentation_submission(
    definition_id: &str,
    matches: Vec<(&str, &str, &str)>, // (descriptor_id, format, path)
) -> PresentationSubmission {
    PresentationSubmission {
        id: format!("submission-{}", definition_id),
        definition_id: definition_id.to_string(),
        descriptor_map: matches
            .into_iter()
            .map(|(id, format, path)| DescriptorMapEntry {
                id: id.to_string(),
                format: format.to_string(),
                path: path.to_string(),
                path_nested: None,
            })
            .collect(),
    }
}

/// Build an authorization response with VP token and submission.
pub fn build_authorization_response(
    vp_token: Value,
    submission: PresentationSubmission,
    state: Option<String>,
) -> AuthorizationResponse {
    AuthorizationResponse {
        vp_token,
        presentation_submission: submission,
        state,
    }
}

/// Check if a presentation definition requires a specific credential format.
pub fn requires_format(definition: &PresentationDefinition, format: &str) -> bool {
    if let Some(ref formats) = definition.format {
        formats.contains_key(format)
    } else {
        // No format restriction — any format accepted
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_submission() {
        let submission = build_presentation_submission(
            "pd-1",
            vec![
                ("age-check", "vc+sd-jwt", "$"),
                ("name-check", "vc+sd-jwt", "$.verifiableCredential[0]"),
            ],
        );

        assert_eq!(submission.definition_id, "pd-1");
        assert_eq!(submission.descriptor_map.len(), 2);
        assert_eq!(submission.descriptor_map[0].id, "age-check");
        assert_eq!(submission.descriptor_map[1].format, "vc+sd-jwt");
    }

    #[test]
    fn build_response() {
        let submission = build_presentation_submission("pd-1", vec![("x", "vc+sd-jwt", "$")]);
        let response = build_authorization_response(
            json!("eyJ...vp_token..."),
            submission,
            Some("state-abc".into()),
        );

        assert_eq!(response.state.as_deref(), Some("state-abc"));
        assert_eq!(response.presentation_submission.definition_id, "pd-1");
    }

    #[test]
    fn parse_request() {
        let json = serde_json::to_string(&json!({
            "response_type": "vp_token",
            "client_id": "https://verifier.example.com",
            "nonce": "abc",
            "presentation_definition": {
                "id": "pd-1",
                "input_descriptors": [{
                    "id": "id-1",
                    "constraints": {
                        "fields": [{"path": ["$.given_name"]}]
                    }
                }]
            }
        }))
        .unwrap();

        let req = parse_authorization_request(&json).unwrap();
        assert_eq!(req.client_id, "https://verifier.example.com");
        assert!(req.presentation_definition.is_some());
    }
}
