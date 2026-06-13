/*!
 * mdoc flows on the [`CredentialScenario`] (TI5b).
 *
 * Extends the shared issuer/holder/verifier fixture with the ISO/IEC 18013-5
 * mdoc path: issue an mdoc whose Mobile Security Object is signed with the
 * issuer's EdDSA COSE key (`sign_mso`), present a selective-disclosure
 * `DeviceResponse` (optionally with a holder device signature), and verify
 * `issuerAuth` (`verify_issuer_auth`) plus the disclosed digests.
 *
 * The same three [`crate::credential_scenario::Party`] identities back both the
 * SD-JWT VC path (TI5a) and this mdoc path, so a test can exercise both eIDAS
 * mandatory credential formats from one scenario. The issuer's Ed25519 key
 * doubles as the EdDSA COSE signing key; the holder's public key is bound into
 * the MSO `deviceKeyInfo` and used for device-auth holder binding.
 *
 * Like the SD-JWT verifier, [`CredentialScenario::verify_mdoc`] enforces an
 * algorithm allowlist (EdDSA) on `issuerAuth` *before* the signature is checked
 * — the W5 principle in the mdoc context, which is what makes the disallowed-
 * `alg` negative ([`crate::credential_scenario::Party::cose_signer_with_alg`])
 * expressible.
 *
 * ```
 * use affinidi_tdk_test_support::credential_scenario::CredentialScenario;
 * use serde_json::json;
 * use std::collections::BTreeMap;
 *
 * let scenario = CredentialScenario::new();
 * let mdoc = scenario
 *     .issue_mdoc(
 *         "eu.europa.ec.eudi.pid.1",
 *         "eu.europa.ec.eudi.pid.1",
 *         &json!({ "given_name": "Erika", "age_over_18": true }),
 *     )
 *     .unwrap();
 *
 * let mut requested = BTreeMap::new();
 * requested.insert("eu.europa.ec.eudi.pid.1".to_string(), vec!["age_over_18".to_string()]);
 * let response = scenario.present_mdoc(&mdoc, &requested).unwrap();
 *
 * let mso = scenario.verify_mdoc(&response).unwrap();
 * assert_eq!(mso.doc_type, "eu.europa.ec.eudi.pid.1");
 * ```
 */

use std::collections::BTreeMap;

use affinidi_mdoc::{
    DeviceResponse, IssuerSigned, MdocBuilder, MobileSecurityObject, SessionTranscript,
    ValidityInfo, cose::CoseSigner, cose::verify_issuer_auth_with_alg,
    device_engagement::DeviceEngagement,
};
use coset::iana::Algorithm as CoseAlgorithm;

use crate::credential_scenario::{CredentialScenario, ScenarioError};

impl CredentialScenario {
    /// Issue an mdoc credential: each entry of the `claims` JSON object becomes
    /// an attribute in `namespace`, the MSO is signed with the issuer's EdDSA
    /// COSE key, and the holder's public key is bound into `deviceKeyInfo`.
    pub fn issue_mdoc(
        &self,
        doc_type: &str,
        namespace: &str,
        claims: &serde_json::Value,
    ) -> Result<IssuerSigned, ScenarioError> {
        self.issue_mdoc_with_signer(&self.issuer.cose_signer(), doc_type, namespace, claims)
    }

    /// Issue with a caller-supplied COSE signer — e.g. a forged-`alg` signer
    /// (`self.issuer.cose_signer_with_alg(..)`) for the disallowed-`alg`
    /// negative.
    pub fn issue_mdoc_with_signer(
        &self,
        signer: &dyn CoseSigner,
        doc_type: &str,
        namespace: &str,
        claims: &serde_json::Value,
    ) -> Result<IssuerSigned, ScenarioError> {
        let object = claims
            .as_object()
            .ok_or_else(|| ScenarioError::Mdoc("mdoc claims must be a JSON object".to_string()))?;
        let mut builder = MdocBuilder::new(doc_type)
            .device_key(self.holder.device_cose_key())
            .validity(default_validity());
        for (id, value) in object {
            builder = builder.add_json_attribute(namespace, id, value);
        }
        builder
            .build(signer)
            .map_err(|e| ScenarioError::Mdoc(e.to_string()))
    }

    /// Holder presents the `requested` attributes (per namespace) with no device
    /// signature — issuer-signed selective disclosure only.
    pub fn present_mdoc(
        &self,
        mdoc: &IssuerSigned,
        requested: &BTreeMap<String, Vec<String>>,
    ) -> Result<DeviceResponse, ScenarioError> {
        DeviceResponse::create(mdoc, requested).map_err(|e| ScenarioError::Mdoc(e.to_string()))
    }

    /// Holder presents with a device signature (holder binding): the device key
    /// signs `DeviceAuthentication` over `transcript`.
    pub fn present_mdoc_with_binding(
        &self,
        mdoc: &IssuerSigned,
        requested: &BTreeMap<String, Vec<String>>,
        transcript: &SessionTranscript,
    ) -> Result<DeviceResponse, ScenarioError> {
        DeviceResponse::create_with_device_auth(
            mdoc,
            requested,
            transcript,
            &self.holder.cose_signer(),
            None,
        )
        .map_err(|e| ScenarioError::Mdoc(e.to_string()))
    }

    /// Verify a device response with the issuer's key and the EdDSA allowlist:
    /// `issuerAuth` algorithm + signature, then every disclosed digest. Returns
    /// the decoded MSO. The default for the happy path; use
    /// [`verify_mdoc_with_alg`](Self::verify_mdoc_with_alg) to assert a
    /// different declared algorithm.
    pub fn verify_mdoc(
        &self,
        response: &DeviceResponse,
    ) -> Result<MobileSecurityObject, ScenarioError> {
        self.verify_mdoc_with_alg(response, CoseAlgorithm::EdDSA)
    }

    /// Verify a device response requiring `expected_alg` in the `issuerAuth`
    /// protected header — the algorithm is checked *before* the signature, so a
    /// credential whose declared `alg` is outside the allowlist is rejected even
    /// though its signature is otherwise valid.
    pub fn verify_mdoc_with_alg(
        &self,
        response: &DeviceResponse,
        expected_alg: CoseAlgorithm,
    ) -> Result<MobileSecurityObject, ScenarioError> {
        let mso = verify_issuer_auth_with_alg(
            &response.issuer_auth,
            &self.issuer.cose_verifier(),
            expected_alg,
        )
        .map_err(|e| ScenarioError::Mdoc(e.to_string()))?;
        if !response
            .verify_digests()
            .map_err(|e| ScenarioError::Mdoc(e.to_string()))?
        {
            return Err(ScenarioError::Mdoc(
                "a disclosed item's digest does not match the MSO".to_string(),
            ));
        }
        Ok(mso)
    }

    /// Verify the holder's device signature against `transcript` and the holder
    /// key. For the wrong-key negative, call
    /// [`DeviceResponse::verify_device_auth`] directly with another party's
    /// [`cose_verifier`](crate::credential_scenario::Party::cose_verifier).
    pub fn verify_mdoc_binding(
        &self,
        response: &DeviceResponse,
        transcript: &SessionTranscript,
    ) -> Result<bool, ScenarioError> {
        response
            .verify_device_auth(transcript, &self.holder.cose_verifier())
            .map_err(|e| ScenarioError::Mdoc(e.to_string()))
    }

    /// A deterministic QR-engagement [`SessionTranscript`] for holder-binding
    /// tests (empty device / reader keys — fixed across runs).
    pub fn session_transcript(&self) -> Result<SessionTranscript, ScenarioError> {
        let engagement = DeviceEngagement::new(ciborium::Value::Map(vec![]))
            .map_err(|e| ScenarioError::Mdoc(e.to_string()))?;
        SessionTranscript::new_qr(&engagement, ciborium::Value::Map(vec![]))
            .map_err(|e| ScenarioError::Mdoc(e.to_string()))
    }
}

/// Fixed validity window for fixture mdocs (TEST-ONLY; dates are arbitrary).
fn default_validity() -> ValidityInfo {
    ValidityInfo {
        signed: "2024-06-15T12:00:00Z".to_string(),
        valid_from: "2024-06-15T12:00:00Z".to_string(),
        valid_until: "2034-06-15T12:00:00Z".to_string(),
    }
}
