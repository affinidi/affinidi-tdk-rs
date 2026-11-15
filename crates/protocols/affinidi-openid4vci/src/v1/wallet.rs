/*!
 * Wallet-side helpers for OpenID4VCI **1.0 Final**.
 *
 * - Credential Offer intake (§4.1) — [`parse_credential_offer_uri`],
 *   [`parse_credential_offer`].
 * - Issuer metadata discovery and checks (§12.2) — [`metadata_url`],
 *   [`check_issuer_metadata`].
 * - Token Request for the Pre-Authorized Code Flow (§6.1) —
 *   [`build_pre_authorized_token_request`].
 * - Credential / Deferred / Notification requests (§8.2, §9.1, §11.1) and
 *   Credential Response checks (§8.3).
 *
 * Key proofs: build each `jwt` proof with
 * [`crate::proof::build_key_proof_jwt`] (one per holder key, `aud` = the
 * Credential Issuer Identifier, `nonce` = the `c_nonce` from the Nonce
 * Endpoint) and wrap them with [`Proofs::jwt`].
 *
 * HTTP transport (and OAuth authorization requests / PKCE) is the caller's.
 */

use super::issuer::{check_credential_offer, check_issuer_identifier};
use super::types::*;
use crate::error::{Oid4vciError, Result};

/// Where a Credential Offer lives (§4.1).
#[derive(Debug, Clone, PartialEq)]
pub enum CredentialOfferSource {
    /// Passed by value in `credential_offer` (§4.1.2).
    ByValue(CredentialOffer),
    /// Passed by reference in `credential_offer_uri` (§4.1.3): `GET` it
    /// (expecting `application/json`) and feed the body to
    /// [`parse_credential_offer`].
    ByReference(url::Url),
}

/// Parse a Credential Offer link / QR payload
/// (`openid-credential-offer://?credential_offer=...` or
/// `...?credential_offer_uri=...`, or the same query on an `https` Credential
/// Offer Endpoint).
///
/// Exactly one of the two parameters must be present (§4.1); a by-reference
/// URL must use `https` (§4.1). A by-value offer is checked like
/// [`parse_credential_offer`].
pub fn parse_credential_offer_uri(uri: &str) -> Result<CredentialOfferSource> {
    let url =
        url::Url::parse(uri).map_err(|e| Oid4vciError::InvalidOffer(format!("not a URI: {e}")))?;
    let mut by_value = None;
    let mut by_reference = None;
    for (name, value) in url.query_pairs() {
        let slot = match name.as_ref() {
            "credential_offer" => &mut by_value,
            "credential_offer_uri" => &mut by_reference,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Err(Oid4vciError::InvalidOffer(format!(
                "parameter `{name}` is repeated"
            )));
        }
    }
    match (by_value, by_reference) {
        (Some(_), Some(_)) => Err(Oid4vciError::InvalidOffer(
            "credential_offer and credential_offer_uri are mutually exclusive".into(),
        )),
        (None, None) => Err(Oid4vciError::InvalidOffer(
            "one of credential_offer or credential_offer_uri is required".into(),
        )),
        (Some(json), None) => parse_credential_offer(&json).map(CredentialOfferSource::ByValue),
        (None, Some(reference)) => {
            let reference = url::Url::parse(&reference).map_err(|e| {
                Oid4vciError::InvalidOffer(format!("credential_offer_uri is not a URL: {e}"))
            })?;
            if reference.scheme() != "https" {
                return Err(Oid4vciError::InvalidOffer(
                    "credential_offer_uri must use the https scheme".into(),
                ));
            }
            Ok(CredentialOfferSource::ByReference(reference))
        }
    }
}

/// Parse and structurally check a Credential Offer JSON object (§4.1.1;
/// see [`check_credential_offer`] for the checks).
pub fn parse_credential_offer(json: &str) -> Result<CredentialOffer> {
    let offer: CredentialOffer =
        serde_json::from_str(json).map_err(|e| Oid4vciError::InvalidOffer(e.to_string()))?;
    check_credential_offer(&offer)?;
    Ok(offer)
}

/// The Credential Issuer Metadata URL (§12.2.2): `/.well-known/openid-credential-issuer`
/// is inserted **between the host and the path** of the Credential Issuer
/// Identifier, e.g. `https://issuer.example.com/tenant` →
/// `https://issuer.example.com/.well-known/openid-credential-issuer/tenant`.
///
/// (The draft-13 helper [`crate::wallet::metadata_url`] appends it instead,
/// which is only equivalent for identifiers without a path.)
pub fn metadata_url(credential_issuer: &str) -> Result<String> {
    let mut url =
        check_issuer_identifier(credential_issuer).map_err(Oid4vciError::InvalidMetadata)?;
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&format!("{WELL_KNOWN_CREDENTIAL_ISSUER}{path}"));
    Ok(url.to_string())
}

/// Check fetched Credential Issuer Metadata (§12.2.2, §12.2.4):
///
/// - `credential_issuer` is **identical** (simple string comparison) to the
///   identifier the metadata was fetched for — otherwise it MUST NOT be used;
/// - the endpoint URLs use `https`;
/// - `credential_configurations_supported` is present (may be empty only if
///   the issuer offers nothing), `batch_size` is at least 2, and the
///   encryption metadata lists are non-empty;
/// - each SD-JWT VC configuration has `vct` and each mdoc configuration has
///   `doctype` (Appendix A.3.2, A.2.2).
pub fn check_issuer_metadata(
    metadata: &CredentialIssuerMetadata,
    expected_credential_issuer: &str,
) -> Result<()> {
    let bad = |m: String| Err(Oid4vciError::InvalidMetadata(m));
    if metadata.credential_issuer != expected_credential_issuer {
        return bad(format!(
            "credential_issuer `{}` does not match `{expected_credential_issuer}`",
            metadata.credential_issuer
        ));
    }
    let endpoints = [
        ("credential_endpoint", Some(&metadata.credential_endpoint)),
        ("nonce_endpoint", metadata.nonce_endpoint.as_ref()),
        (
            "deferred_credential_endpoint",
            metadata.deferred_credential_endpoint.as_ref(),
        ),
        (
            "notification_endpoint",
            metadata.notification_endpoint.as_ref(),
        ),
    ];
    for (name, value) in endpoints {
        if let Some(v) = value {
            let ok = url::Url::parse(v).is_ok_and(|u| u.scheme() == "https");
            if !ok {
                return bad(format!("{name} must be an https URL"));
            }
        }
    }
    if let Some(batch) = metadata.batch_credential_issuance
        && batch.batch_size < 2
    {
        return bad("batch_credential_issuance.batch_size must be 2 or greater".into());
    }
    if let Some(enc) = &metadata.credential_request_encryption
        && (enc.enc_values_supported.is_empty() || enc.jwks.keys().is_empty())
    {
        return bad("credential_request_encryption needs keys and enc values".into());
    }
    if let Some(enc) = &metadata.credential_response_encryption
        && (enc.alg_values_supported.is_empty() || enc.enc_values_supported.is_empty())
    {
        return bad("credential_response_encryption needs alg and enc values".into());
    }
    for (id, config) in &metadata.credential_configurations_supported {
        if config.format == FORMAT_DC_SD_JWT && config.vct.is_none() {
            return bad(format!(
                "configuration `{id}`: vct is required for dc+sd-jwt"
            ));
        }
        if config.format == FORMAT_MSO_MDOC && config.doctype.is_none() {
            return bad(format!(
                "configuration `{id}`: doctype is required for mso_mdoc"
            ));
        }
    }
    Ok(())
}

/// Find the first configuration of a given format.
pub fn find_credential_configuration<'a>(
    metadata: &'a CredentialIssuerMetadata,
    format: &str,
) -> Option<(&'a String, &'a CredentialConfiguration)> {
    metadata
        .credential_configurations_supported
        .iter()
        .find(|(_, c)| c.format == format)
}

/// Build the Token Request for the Pre-Authorized Code Flow (§6.1).
///
/// `tx_code` must be supplied iff the offer's grant carries a `tx_code`
/// object (even an empty one). When the grant states an input mode
/// (default `numeric`) or a length, the supplied code is checked against
/// them before it is sent.
pub fn build_pre_authorized_token_request(
    grant: &PreAuthorizedCodeGrant,
    tx_code: Option<String>,
) -> Result<TokenRequest> {
    match (&grant.tx_code, &tx_code) {
        (Some(_), None) => {
            return Err(Oid4vciError::InvalidRequest(
                "the offer requires a tx_code".into(),
            ));
        }
        (None, Some(_)) => {
            return Err(Oid4vciError::InvalidRequest(
                "the offer does not expect a tx_code".into(),
            ));
        }
        (Some(spec), Some(code)) => {
            if spec.effective_input_mode() == TxCodeInputMode::Numeric
                && !code.chars().all(|c| c.is_ascii_digit())
            {
                return Err(Oid4vciError::InvalidRequest(
                    "tx_code must be numeric".into(),
                ));
            }
            if let Some(len) = spec.length
                && code.chars().count() != len as usize
            {
                return Err(Oid4vciError::InvalidRequest(format!(
                    "tx_code must be {len} characters long"
                )));
            }
        }
        (None, None) => {}
    }
    Ok(TokenRequest {
        grant_type: GRANT_TYPE_PRE_AUTHORIZED_CODE.to_string(),
        pre_authorized_code: Some(grant.pre_authorized_code.clone()),
        tx_code,
        ..TokenRequest::default()
    })
}

/// The `credential_identifiers` a Token Response authorized for one
/// configuration (§6.2). Empty when the AS returned none, in which case the
/// Credential Request uses `credential_configuration_id` (§3.3.4).
pub fn credential_identifiers<'a>(
    response: &'a TokenResponse,
    credential_configuration_id: &str,
) -> Vec<&'a str> {
    response
        .authorization_details
        .iter()
        .flatten()
        .filter(|d| {
            d.detail_type == AUTHORIZATION_DETAILS_TYPE_OPENID_CREDENTIAL
                && d.credential_configuration_id == credential_configuration_id
        })
        .flat_map(|d| d.credential_identifiers.iter().flatten())
        .map(String::as_str)
        .collect()
}

/// A Credential Request naming a configuration (§8.2; use when the Token
/// Response returned no `credential_identifiers`).
pub fn build_credential_request_for_configuration(
    credential_configuration_id: impl Into<String>,
    proofs: Option<Proofs>,
) -> CredentialRequest {
    CredentialRequest {
        credential_configuration_id: Some(credential_configuration_id.into()),
        proofs,
        ..CredentialRequest::default()
    }
}

/// A Credential Request naming a Credential Dataset from the Token Response
/// (§8.2).
pub fn build_credential_request_for_identifier(
    credential_identifier: impl Into<String>,
    proofs: Option<Proofs>,
) -> CredentialRequest {
    CredentialRequest {
        credential_identifier: Some(credential_identifier.into()),
        proofs,
        ..CredentialRequest::default()
    }
}

/// A Deferred Credential Request (§9.1).
pub fn build_deferred_credential_request(
    transaction_id: impl Into<String>,
) -> DeferredCredentialRequest {
    DeferredCredentialRequest {
        transaction_id: transaction_id.into(),
        credential_response_encryption: None,
        additional: Additional::new(),
    }
}

/// A Notification Request (§11.1).
pub fn build_notification_request(
    notification_id: impl Into<String>,
    event: NotificationEvent,
    event_description: Option<String>,
) -> NotificationRequest {
    NotificationRequest {
        notification_id: notification_id.into(),
        event,
        event_description,
        additional: Additional::new(),
    }
}

/// Check a (Deferred) Credential Response (§8.3, §9.2): the member rules of
/// [`CredentialResponse::check`], and no more credentials than key proofs
/// sent (`key_proofs_sent`; pass 1 for a request without proofs).
pub fn check_credential_response(
    response: &CredentialResponse,
    key_proofs_sent: usize,
) -> Result<()> {
    response
        .check()
        .map_err(|m| Oid4vciError::InvalidResponse(m.into()))?;
    if let Some(creds) = &response.credentials
        && creds.len() > key_proofs_sent.max(1)
    {
        return Err(Oid4vciError::InvalidResponse(format!(
            "{} credentials returned for {key_proofs_sent} key proofs",
            creds.len()
        )));
    }
    Ok(())
}
