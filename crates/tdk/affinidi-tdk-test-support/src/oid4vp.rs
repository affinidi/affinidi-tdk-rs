/*!
 * OpenID4VP present/verify flows on the [`CredentialScenario`] (TI5b).
 *
 * Wires the scenario's credentials into the OID4VP authorization
 * request/response envelope (from `affinidi-openid4vp`) so an issue → present →
 * verify round trip can be driven through OID4VP rather than as a bare crypto
 * call. Both eIDAS mandatory formats are covered:
 *
 * - **`vc+sd-jwt`** — the `vp_token` is the SD-JWT VC's compact serialization
 *   (`<issuer-jwt>~<disclosure>~…~<kb-jwt>`), exactly the OID4VP wire form. The
 *   KB-JWT is bound to the request's `client_id` (audience) and `nonce`.
 * - **`mso_mdoc`** — the `vp_token` is a base64url-encoded CBOR transport of the
 *   mdoc [`DeviceResponse`] (see [`encode_device_response`]).
 *
 * On the verifier side, [`CredentialScenario::oid4vp_verify_sd_jwt`] /
 * [`oid4vp_verify_mdoc`](CredentialScenario::oid4vp_verify_mdoc) first validate
 * the envelope (definition id, state, non-empty descriptor map) with
 * `affinidi-openid4vp`, then cryptographically verify the carried credential
 * with the scenario's verifiers — so an envelope that parses but carries an
 * invalid or replayed credential is still rejected.
 *
 * ```
 * use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
 * use affinidi_openid4vp::{PresentationDefinition, verifier::create_input_descriptor};
 * use serde_json::json;
 *
 * let scenario = CredentialScenario::new();
 * let definition = PresentationDefinition {
 *     id: "pd-1".into(),
 *     name: None,
 *     purpose: None,
 *     input_descriptors: vec![create_input_descriptor("cred", "identity", vec![("given_name", None)])],
 *     submission_requirements: None,
 *     format: None,
 * };
 * let request = scenario.oid4vp_request("https://verifier.example", "nonce-1", definition);
 *
 * let vc = scenario
 *     .issue_sd_jwt_vc(
 *         "https://example.com/IdentityCredential",
 *         &json!({ "given_name": "Alice" }),
 *         &json!({ "_sd": ["given_name"] }),
 *     )
 *     .unwrap();
 * let response = scenario.oid4vp_present_sd_jwt(&request, &vc, &["given_name"]).unwrap();
 * let result = scenario.oid4vp_verify_sd_jwt(&request, &response).unwrap();
 * assert!(result.is_verified());
 * ```
 */

use std::collections::BTreeMap;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use affinidi_mdoc::{
    DeviceResponse, IssuerSigned, IssuerSignedItem, MobileSecurityObject, Tag24,
    cose::verify_issuer_auth_with_alg,
};
use affinidi_openid4vp::{
    AuthorizationRequest, AuthorizationResponse, PresentationDefinition,
    verifier::{create_authorization_request, validate_authorization_response},
    wallet::{build_authorization_response, build_presentation_submission},
};
use affinidi_sd_jwt::{SdJwt, hasher::Sha256Hasher, verifier::VerificationResult};
use affinidi_vc::sd_jwt_vc::SdJwtVc;
use coset::{CborSerializable, CoseSign1, iana::Algorithm as CoseAlgorithm};

use crate::credential_scenario::{CredentialScenario, ScenarioError};

/// OID4VP credential-format identifier for SD-JWT VC.
pub const FORMAT_SD_JWT_VC: &str = "vc+sd-jwt";
/// OID4VP credential-format identifier for ISO mdoc.
pub const FORMAT_MSO_MDOC: &str = "mso_mdoc";

/// Disclosed mdoc items, grouped by namespace (Tag24-wrapped per ISO 18013-5).
type DisclosedNamespaces = BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>;

impl CredentialScenario {
    /// Build a verifier OID4VP authorization request (`response_type=vp_token`,
    /// `direct_post`) for `definition`. The `client_id` is the KB-JWT audience
    /// and `nonce` the replay nonce a holder must echo.
    pub fn oid4vp_request(
        &self,
        client_id: &str,
        nonce: &str,
        definition: PresentationDefinition,
    ) -> AuthorizationRequest {
        let redirect_uri = format!("{client_id}/callback");
        create_authorization_request(client_id, &redirect_uri, nonce, definition)
    }

    /// Holder answers `request` by presenting an SD-JWT VC, revealing `reveal`.
    /// The KB-JWT is bound to the request's `client_id` and `nonce`; the result
    /// is an [`AuthorizationResponse`] with a `vc+sd-jwt` `vp_token`.
    pub fn oid4vp_present_sd_jwt(
        &self,
        request: &AuthorizationRequest,
        vc: &SdJwtVc,
        reveal: &[&str],
    ) -> Result<AuthorizationResponse, ScenarioError> {
        let presentation = self.present(vc, reveal, &request.client_id, &request.nonce)?;
        let vp_token = Value::String(presentation.serialize());
        let submission = build_presentation_submission(
            definition_id(request)?,
            vec![(descriptor_id(request)?, FORMAT_SD_JWT_VC, "$")],
        );
        Ok(build_authorization_response(
            vp_token,
            submission,
            request.state.clone(),
        ))
    }

    /// Verifier validates the OID4VP envelope and cryptographically verifies the
    /// SD-JWT VC carried in the `vp_token` (issuer signature, KB-JWT binding to
    /// `client_id`/`nonce`, EdDSA allowlist). Returns the verification result.
    pub fn oid4vp_verify_sd_jwt(
        &self,
        request: &AuthorizationRequest,
        response: &AuthorizationResponse,
    ) -> Result<VerificationResult, ScenarioError> {
        validate_authorization_response(
            response,
            definition_id(request)?,
            request.state.as_deref(),
        )
        .map_err(|e| ScenarioError::Oid4vp(e.to_string()))?;
        let token = vp_token_str(response)?;
        let presentation =
            SdJwt::parse(token, &Sha256Hasher).map_err(|e| ScenarioError::SdJwt(e.to_string()))?;
        self.verify(&presentation, &request.client_id, &request.nonce)
    }

    /// Holder answers `request` by presenting an mdoc, revealing `requested`
    /// (per namespace). The [`DeviceResponse`] is CBOR-encoded and
    /// base64url-wrapped as an `mso_mdoc` `vp_token`.
    pub fn oid4vp_present_mdoc(
        &self,
        request: &AuthorizationRequest,
        mdoc: &IssuerSigned,
        requested: &BTreeMap<String, Vec<String>>,
    ) -> Result<AuthorizationResponse, ScenarioError> {
        let device_response = self.present_mdoc(mdoc, requested)?;
        let vp_token = Value::String(encode_device_response(&device_response)?);
        let submission = build_presentation_submission(
            definition_id(request)?,
            vec![(descriptor_id(request)?, FORMAT_MSO_MDOC, "$")],
        );
        Ok(build_authorization_response(
            vp_token,
            submission,
            request.state.clone(),
        ))
    }

    /// Verifier validates the OID4VP envelope, decodes the mdoc `vp_token`, and
    /// verifies `issuerAuth` (EdDSA allowlist) plus every disclosed digest.
    /// Returns the decoded MSO.
    pub fn oid4vp_verify_mdoc(
        &self,
        request: &AuthorizationRequest,
        response: &AuthorizationResponse,
    ) -> Result<MobileSecurityObject, ScenarioError> {
        validate_authorization_response(
            response,
            definition_id(request)?,
            request.state.as_deref(),
        )
        .map_err(|e| ScenarioError::Oid4vp(e.to_string()))?;
        let token = vp_token_str(response)?;
        let (issuer_auth, disclosed) = decode_device_response(token)?;
        let mso = verify_issuer_auth_with_alg(
            &issuer_auth,
            &self.issuer.cose_verifier(),
            CoseAlgorithm::EdDSA,
        )
        .map_err(|e| ScenarioError::Mdoc(e.to_string()))?;
        for (namespace, items) in &disclosed {
            for item in items {
                if !mso
                    .verify_item_digest(namespace, &item.inner)
                    .map_err(|e| ScenarioError::Mdoc(e.to_string()))?
                {
                    return Err(ScenarioError::Mdoc(
                        "a disclosed item's digest does not match the MSO".to_string(),
                    ));
                }
            }
        }
        Ok(mso)
    }
}

// ── OID4VP envelope helpers ──────────────────────────────────────────────────

fn definition_id(request: &AuthorizationRequest) -> Result<&str, ScenarioError> {
    request
        .presentation_definition
        .as_ref()
        .map(|d| d.id.as_str())
        .ok_or_else(|| ScenarioError::Oid4vp("request has no presentation_definition".to_string()))
}

fn descriptor_id(request: &AuthorizationRequest) -> Result<&str, ScenarioError> {
    request
        .presentation_definition
        .as_ref()
        .and_then(|d| d.input_descriptors.first())
        .map(|d| d.id.as_str())
        .ok_or_else(|| ScenarioError::Oid4vp("request has no input descriptor".to_string()))
}

fn vp_token_str(response: &AuthorizationResponse) -> Result<&str, ScenarioError> {
    response
        .vp_token
        .as_str()
        .ok_or_else(|| ScenarioError::Oid4vp("vp_token is not a string".to_string()))
}

// ── mdoc DeviceResponse transport ────────────────────────────────────────────

/// The fixture's wire encoding of a [`DeviceResponse`] for the `mso_mdoc`
/// `vp_token`. This is a **test transport**, not the ISO/IEC 18013-7
/// `DeviceResponse` CBOR (there is no SessionTranscript / OID4VP handover
/// binding) — it carries just enough (the issuer-signed COSE_Sign1 and the
/// disclosed items) to round-trip the credential through the OID4VP envelope and
/// re-verify it.
#[derive(Serialize, Deserialize)]
struct DeviceResponseTransport {
    version: String,
    doc_type: String,
    issuer_auth: Vec<u8>,
    namespaces: BTreeMap<String, Vec<Tag24<IssuerSignedItem>>>,
    status: u32,
}

/// Encode a [`DeviceResponse`] as the base64url(CBOR) `mso_mdoc` `vp_token`.
pub fn encode_device_response(response: &DeviceResponse) -> Result<String, ScenarioError> {
    let issuer_auth = response
        .issuer_auth
        .clone()
        .to_vec()
        .map_err(|e| ScenarioError::Mdoc(format!("issuerAuth encode: {e}")))?;
    let transport = DeviceResponseTransport {
        version: response.version.clone(),
        doc_type: response.doc_type.clone(),
        issuer_auth,
        namespaces: response.disclosed.clone(),
        status: response.status,
    };
    let mut buf = Vec::new();
    ciborium::into_writer(&transport, &mut buf)
        .map_err(|e| ScenarioError::Mdoc(format!("DeviceResponse encode: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// Decode an `mso_mdoc` `vp_token` into its `issuerAuth` and disclosed items.
fn decode_device_response(token: &str) -> Result<(CoseSign1, DisclosedNamespaces), ScenarioError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|e| ScenarioError::Mdoc(format!("vp_token base64: {e}")))?;
    let transport: DeviceResponseTransport = ciborium::from_reader(&bytes[..])
        .map_err(|e| ScenarioError::Mdoc(format!("DeviceResponse decode: {e}")))?;
    let issuer_auth = CoseSign1::from_slice(&transport.issuer_auth)
        .map_err(|e| ScenarioError::Mdoc(format!("issuerAuth decode: {e}")))?;
    Ok((issuer_auth, transport.namespaces))
}
