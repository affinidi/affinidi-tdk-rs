/*!
 * Issuer-side helpers for OpenID4VCI **1.0 Final**.
 *
 * - Credential Offer construction (§4.1) — [`create_pre_authorized_offer`],
 *   [`create_authorization_code_offer`], [`credential_offer_by_value_uri`].
 * - Pre-Authorized Code Token Request checks, including `tx_code` (§6.1,
 *   §6.3) — [`check_pre_authorized_token_request`].
 * - Credential Request validation against the issuer's metadata (§8.2) —
 *   [`validate_credential_request`].
 * - `jwt` key proof verification for a whole `proofs` array (§8.2,
 *   Appendix F.1, F.4), reusing the version-independent [`crate::proof`]
 *   module — [`verify_jwt_proofs`].
 *
 * Failures are returned as the wire error bodies ([`TokenErrorResponse`],
 * [`CredentialErrorResponse`]) carrying the error code the spec mandates, so
 * an endpoint can serialize them straight into the HTTP 400 response.
 *
 * Not covered: access-token issuance and validation, single-use bookkeeping
 * of pre-authorized codes and nonces, nonce generation, JWE encryption of
 * requests/responses (§10), and the `di_vp` / `attestation` proof
 * verification (those proofs are only checked structurally).
 */

use affinidi_oid4vc_core::jwt::JwtVerifier;

use super::types::*;
use crate::error::{Oid4vciError, Result};
use crate::proof::{KeyProof, ProofPolicy};

// ── Credential Offer (§4.1) ─────────────────────────────────────────────────

/// Build a Credential Offer for the Pre-Authorized Code Flow (§3.5, §4.1.1).
///
/// Pass `tx_code: Some(..)` (an empty [`TxCode`] is fine) when the Token
/// Request must carry a Transaction Code; deliver the code itself out of
/// band and check it with [`check_pre_authorized_token_request`].
pub fn create_pre_authorized_offer(
    credential_issuer: &str,
    credential_configuration_ids: Vec<String>,
    pre_authorized_code: String,
    tx_code: Option<TxCode>,
) -> Result<CredentialOffer> {
    let offer = CredentialOffer {
        credential_issuer: credential_issuer.to_string(),
        credential_configuration_ids,
        grants: Some(Grants {
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code,
                tx_code,
                authorization_server: None,
            }),
            ..Grants::default()
        }),
        additional: Additional::new(),
    };
    check_credential_offer(&offer)?;
    Ok(offer)
}

/// Build a Credential Offer for the Authorization Code Flow (§3.4, §4.1.1).
pub fn create_authorization_code_offer(
    credential_issuer: &str,
    credential_configuration_ids: Vec<String>,
    issuer_state: Option<String>,
) -> Result<CredentialOffer> {
    let offer = CredentialOffer {
        credential_issuer: credential_issuer.to_string(),
        credential_configuration_ids,
        grants: Some(Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state,
                authorization_server: None,
            }),
            ..Grants::default()
        }),
        additional: Additional::new(),
    };
    check_credential_offer(&offer)?;
    Ok(offer)
}

/// Structural checks on a Credential Offer (§4.1.1): an `https` Credential
/// Issuer Identifier without query or fragment (§12.2.1), a non-empty array
/// of unique `credential_configuration_ids`, a non-empty
/// `pre-authorized_code`, and a `tx_code.description` of at most 300
/// characters.
pub fn check_credential_offer(offer: &CredentialOffer) -> Result<()> {
    check_issuer_identifier(&offer.credential_issuer).map_err(Oid4vciError::InvalidOffer)?;
    let ids = &offer.credential_configuration_ids;
    if ids.is_empty() {
        return Err(Oid4vciError::InvalidOffer(
            "credential_configuration_ids must not be empty".into(),
        ));
    }
    let unique: std::collections::BTreeSet<&String> = ids.iter().collect();
    if unique.len() != ids.len() {
        return Err(Oid4vciError::InvalidOffer(
            "credential_configuration_ids must be unique".into(),
        ));
    }
    if let Some(pre) = offer
        .grants
        .as_ref()
        .and_then(|g| g.pre_authorized_code.as_ref())
    {
        if pre.pre_authorized_code.is_empty() {
            return Err(Oid4vciError::InvalidOffer(
                "pre-authorized_code must not be empty".into(),
            ));
        }
        if let Some(desc) = pre.tx_code.as_ref().and_then(|t| t.description.as_ref())
            && desc.chars().count() > TX_CODE_DESCRIPTION_MAX_CHARS
        {
            return Err(Oid4vciError::InvalidOffer(format!(
                "tx_code.description exceeds {TX_CODE_DESCRIPTION_MAX_CHARS} characters"
            )));
        }
    }
    Ok(())
}

/// Encode an offer by value for the Wallet's Credential Offer Endpoint
/// (§4.1.2): `openid-credential-offer://?credential_offer=<json>`.
///
/// For large offers prefer passing it by reference (§4.1.3): serve the JSON
/// at an `https` URL and use [`credential_offer_by_reference_uri`].
pub fn credential_offer_by_value_uri(offer: &CredentialOffer) -> Result<String> {
    let json = serde_json::to_string(offer)?;
    let encoded: String = url::form_urlencoded::byte_serialize(json.as_bytes()).collect();
    Ok(format!(
        "{CREDENTIAL_OFFER_SCHEME}://?credential_offer={encoded}"
    ))
}

/// Encode an offer by reference (§4.1.3):
/// `openid-credential-offer://?credential_offer_uri=<url>`.
pub fn credential_offer_by_reference_uri(credential_offer_uri: &str) -> String {
    let encoded: String =
        url::form_urlencoded::byte_serialize(credential_offer_uri.as_bytes()).collect();
    format!("{CREDENTIAL_OFFER_SCHEME}://?credential_offer_uri={encoded}")
}

/// A Credential Issuer Identifier is an `https` URL with a host and no query
/// or fragment (§12.2.1).
pub(crate) fn check_issuer_identifier(id: &str) -> std::result::Result<url::Url, String> {
    let url = url::Url::parse(id).map_err(|e| format!("credential_issuer is not a URL: {e}"))?;
    if url.scheme() != "https" {
        return Err("credential_issuer must use the https scheme".into());
    }
    if url.host().is_none() {
        return Err("credential_issuer must have a host".into());
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("credential_issuer must not have a query or fragment".into());
    }
    Ok(url)
}

// ── Token Endpoint, Pre-Authorized Code grant (§6) ──────────────────────────

/// The issuer's record of a Pre-Authorized Code it put in an offer.
#[derive(Clone)]
pub struct IssuedPreAuthorizedCode {
    /// The code sent in the offer.
    pub pre_authorized_code: String,
    /// The Transaction Code the End-User must present, when the offer carried
    /// a `tx_code` object. `Some` here must correspond to `tx_code` being
    /// present in the offer.
    pub tx_code: Option<String>,
    /// Expiry (seconds since the Unix epoch). The code MUST be short-lived
    /// (§4.1.1); `None` disables the check.
    pub expires_at: Option<i64>,
}

impl std::fmt::Debug for IssuedPreAuthorizedCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuedPreAuthorizedCode")
            .field("pre_authorized_code", &"[REDACTED]")
            .field("tx_code", &self.tx_code.as_ref().map(|_| "[REDACTED]"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Check a Token Request in the Pre-Authorized Code Flow against the
/// issued code (§6.1, error codes per §6.3):
///
/// - `grant_type` is the pre-authorized code grant, else
///   `unsupported_grant_type`;
/// - `pre-authorized_code` present (`invalid_request`), equal to the issued
///   code and not expired (`invalid_grant`);
/// - `tx_code` present iff one was issued (`invalid_request` when missing or
///   unexpected) and equal to it (`invalid_grant`).
///
/// Secrets are compared in constant time. The caller still has to enforce
/// single use (§4.1.1: the code MUST be single use), client authentication /
/// anonymous-access policy, and `authorization_details` authorization.
pub fn check_pre_authorized_token_request(
    request: &TokenRequest,
    issued: &IssuedPreAuthorizedCode,
    now: i64,
) -> std::result::Result<(), TokenErrorResponse> {
    let err = |code, msg: &str| TokenErrorResponse::new(code).with_description(msg);

    if request.grant_type != GRANT_TYPE_PRE_AUTHORIZED_CODE {
        return Err(err(
            TokenErrorCode::UnsupportedGrantType,
            "expected the pre-authorized_code grant type",
        ));
    }
    let Some(code) = request.pre_authorized_code.as_deref() else {
        return Err(err(
            TokenErrorCode::InvalidRequest,
            "pre-authorized_code is required",
        ));
    };
    if !constant_time_eq(code.as_bytes(), issued.pre_authorized_code.as_bytes()) {
        return Err(err(
            TokenErrorCode::InvalidGrant,
            "pre-authorized_code is invalid",
        ));
    }
    if let Some(exp) = issued.expires_at
        && now >= exp
    {
        return Err(err(
            TokenErrorCode::InvalidGrant,
            "pre-authorized_code has expired",
        ));
    }
    match (issued.tx_code.as_deref(), request.tx_code.as_deref()) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(err(
            TokenErrorCode::InvalidRequest,
            "tx_code was not expected",
        )),
        (Some(_), None) => Err(err(TokenErrorCode::InvalidRequest, "tx_code is required")),
        (Some(expected), Some(given)) => {
            if constant_time_eq(given.as_bytes(), expected.as_bytes()) {
                Ok(())
            } else {
                Err(err(TokenErrorCode::InvalidGrant, "tx_code is invalid"))
            }
        }
    }
}

/// Byte comparison whose running time does not depend on where the inputs
/// differ (it does leak whether the lengths differ).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ── Credential Endpoint (§8) ────────────────────────────────────────────────

/// A Credential Request that passed [`validate_credential_request`].
#[derive(Debug, Clone)]
pub struct ValidatedCredentialRequest<'m> {
    /// The configuration id the request resolved to.
    pub credential_configuration_id: &'m str,
    /// The resolved configuration.
    pub configuration: &'m CredentialConfiguration,
    /// The proof type used and the number of key proofs (= the maximum
    /// number of credentials to issue), if `proofs` was sent.
    pub proofs: Option<(String, usize)>,
}

/// Validate a Credential Request against the issuer's metadata (§8.2),
/// returning the §8.3.1.2 error to send on failure.
///
/// `resolve_identifier` maps a `credential_identifier` (from the Token
/// Response's `authorization_details`, bound to the access token) to its
/// configuration id; return `None` for identifiers this access token does
/// not cover.
///
/// Checks:
/// - exactly one of `credential_identifier` / `credential_configuration_id`
///   (`invalid_credential_request`), and that it is known
///   (`unknown_credential_identifier` / `unknown_credential_configuration`);
/// - `proofs` is present when the configuration lists
///   `proof_types_supported`, has exactly one proof type that the
///   configuration supports, a non-empty array no longer than the batch
///   size (`batch_credential_issuance.batch_size`, else 1), and exactly one
///   element for `attestation` (`invalid_proof`);
/// - `credential_response_encryption` is present when the issuer requires
///   it, and its `jwk.alg` / `enc` / `zip` are among the advertised values;
///   the JWK carries no private key (`invalid_encryption_parameters`).
///
/// **Structural only — key proofs are not verified here.** Verify `jwt`
/// proofs with [`verify_jwt_proofs`] before issuing. Whether the request
/// arrived encrypted (§10; required when it carries
/// `credential_response_encryption`) is a transport concern for the caller.
pub fn validate_credential_request<'m>(
    request: &CredentialRequest,
    metadata: &'m CredentialIssuerMetadata,
    resolve_identifier: impl FnOnce(&str) -> Option<String>,
) -> std::result::Result<ValidatedCredentialRequest<'m>, CredentialErrorResponse> {
    let err = |code, msg: String| CredentialErrorResponse::new(code).with_description(msg);

    let (credential_configuration_id, configuration) = match (
        request.credential_identifier.as_deref(),
        request.credential_configuration_id.as_deref(),
    ) {
        (Some(_), Some(_)) => {
            return Err(err(
                CredentialErrorCode::InvalidCredentialRequest,
                "credential_identifier and credential_configuration_id are mutually exclusive"
                    .into(),
            ));
        }
        (None, None) => {
            return Err(err(
                CredentialErrorCode::InvalidCredentialRequest,
                "one of credential_identifier or credential_configuration_id is required".into(),
            ));
        }
        (None, Some(id)) => metadata
            .credential_configurations_supported
            .get_key_value(id)
            .ok_or_else(|| {
                err(
                    CredentialErrorCode::UnknownCredentialConfiguration,
                    format!("unknown credential_configuration_id `{id}`"),
                )
            })?,
        (Some(identifier), None) => {
            let unknown = || {
                err(
                    CredentialErrorCode::UnknownCredentialIdentifier,
                    "unknown credential_identifier".into(),
                )
            };
            let config_id = resolve_identifier(identifier).ok_or_else(unknown)?;
            metadata
                .credential_configurations_supported
                .get_key_value(config_id.as_str())
                .ok_or_else(unknown)?
        }
    };

    let proofs = check_proofs(request, metadata, configuration)
        .map_err(|m| err(CredentialErrorCode::InvalidProof, m))?;

    check_response_encryption(
        request.credential_response_encryption.as_ref(),
        metadata.credential_response_encryption.as_ref(),
    )
    .map_err(|m| err(CredentialErrorCode::InvalidEncryptionParameters, m))?;

    Ok(ValidatedCredentialRequest {
        credential_configuration_id: credential_configuration_id.as_str(),
        configuration,
        proofs,
    })
}

fn check_proofs(
    request: &CredentialRequest,
    metadata: &CredentialIssuerMetadata,
    configuration: &CredentialConfiguration,
) -> std::result::Result<Option<(String, usize)>, String> {
    let supported = configuration.proof_types_supported.as_ref();
    let Some(proofs) = &request.proofs else {
        return match supported {
            Some(_) => Err("proofs is required for this credential configuration".into()),
            None => Ok(None),
        };
    };
    let (proof_type, count) = proofs
        .single()
        .ok_or("proofs must contain exactly one proof type")?;
    let Some(supported) = supported else {
        return Err("this credential configuration does not accept key proofs".into());
    };
    if !supported.contains_key(proof_type) {
        return Err(format!(
            "proof type `{proof_type}` is not supported for this credential configuration"
        ));
    }
    if count == 0 {
        return Err("proofs array must not be empty".into());
    }
    if proof_type == PROOF_TYPE_ATTESTATION && count != 1 {
        return Err("the attestation proof type carries exactly one key attestation".into());
    }
    let max = metadata
        .batch_credential_issuance
        .map_or(1, |b| b.batch_size as usize);
    if count > max {
        return Err(format!("{count} key proofs exceed the batch size of {max}"));
    }
    if let Some(jwts) = &proofs.jwt
        && jwts.iter().any(String::is_empty)
    {
        return Err("jwt proofs must not be empty strings".into());
    }
    Ok(Some((proof_type.to_string(), count)))
}

fn check_response_encryption(
    requested: Option<&CredentialResponseEncryption>,
    supported: Option<&CredentialResponseEncryptionMetadata>,
) -> std::result::Result<(), String> {
    let (requested, supported) = match (requested, supported) {
        (None, Some(s)) if s.encryption_required => {
            return Err("this issuer requires credential_response_encryption".into());
        }
        (None, _) => return Ok(()),
        (Some(_), None) => {
            return Err("this issuer does not support credential response encryption".into());
        }
        (Some(r), Some(s)) => (r, s),
    };
    let jwk = requested
        .jwk
        .as_object()
        .ok_or("credential_response_encryption.jwk must be a JWK object")?;
    if jwk.contains_key("d") {
        return Err("credential_response_encryption.jwk must be a public key".into());
    }
    let alg = jwk
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or("credential_response_encryption.jwk must carry `alg` (section 10)")?;
    if !supported.alg_values_supported.iter().any(|a| a == alg) {
        return Err(format!("JWE alg `{alg}` is not supported"));
    }
    if !supported.enc_values_supported.contains(&requested.enc) {
        return Err(format!("JWE enc `{}` is not supported", requested.enc));
    }
    if let Some(zip) = &requested.zip {
        let ok = supported
            .zip_values_supported
            .as_ref()
            .is_some_and(|z| z.contains(zip));
        if !ok {
            return Err(format!("JWE zip `{zip}` is not supported"));
        }
    }
    Ok(())
}

/// Cryptographically verify every `jwt` key proof of a Credential Request
/// (§8.2, Appendix F.1, F.4) and return the proven proofs, one per
/// credential to issue.
///
/// For each JWT: [`KeyProof::parse`] (typ / alg / key identification), the
/// caller's `resolve_verifier` maps the proof's `kid` / `jwk` to a verifier
/// (see the caller contract on
/// [`KeyProof::verify_signature`](crate::proof::KeyProof::verify_signature);
/// return `None` if the key cannot be resolved), then signature, `aud`,
/// `c_nonce` and freshness per `policy`.
///
/// `allowed_algs` is intersected with the configuration's
/// `proof_types_supported.jwt.proof_signing_alg_values_supported`
/// (F.1: the proof `alg` MUST be one of those).
///
/// Errors: `invalid_nonce` when a proof carries a `c_nonce` other than
/// `policy.nonce`; `invalid_proof` for everything else, including a proof
/// with no `nonce` while one was issued (§8.3.1.2), or a request without
/// `jwt` proofs.
///
/// Key attestations in the `key_attestation` header and `x5c`-identified
/// keys are not evaluated (the [`crate::proof`] parser requires `kid` or
/// `jwk`).
pub fn verify_jwt_proofs(
    request: &CredentialRequest,
    configuration: &CredentialConfiguration,
    mut resolve_verifier: impl FnMut(&KeyProof) -> Option<Box<dyn JwtVerifier>>,
    allowed_algs: &[&str],
    policy: &ProofPolicy<'_>,
) -> std::result::Result<Vec<KeyProof>, CredentialErrorResponse> {
    let invalid = |msg: String| {
        CredentialErrorResponse::new(CredentialErrorCode::InvalidProof).with_description(msg)
    };
    let jwts = request
        .proofs
        .as_ref()
        .and_then(|p| p.jwt.as_ref())
        .filter(|j| !j.is_empty())
        .ok_or_else(|| invalid("no jwt key proofs in the request".into()))?;

    let algs: Vec<&str> = match configuration
        .proof_types_supported
        .as_ref()
        .and_then(|p| p.get(PROOF_TYPE_JWT))
    {
        Some(meta) => allowed_algs
            .iter()
            .copied()
            .filter(|a| {
                meta.proof_signing_alg_values_supported
                    .iter()
                    .any(|s| s == a)
            })
            .collect(),
        None => allowed_algs.to_vec(),
    };

    let mut proven = Vec::with_capacity(jwts.len());
    for jwt in jwts {
        let proof = KeyProof::parse(jwt).map_err(|e| invalid(e.to_string()))?;
        let verifier = resolve_verifier(&proof)
            .ok_or_else(|| invalid("key proof key could not be resolved".into()))?;
        proof
            .verify_signature(&*verifier, &algs)
            .map_err(|e| invalid(e.to_string()))?;
        if let Some(expected) = policy.nonce {
            match proof.claims().nonce.as_deref() {
                None => return Err(invalid("key proof does not contain the c_nonce".into())),
                Some(n) if n != expected => {
                    return Err(
                        CredentialErrorResponse::new(CredentialErrorCode::InvalidNonce)
                            .with_description("key proof c_nonce is invalid; fetch a new one"),
                    );
                }
                Some(_) => {}
            }
        }
        proof
            .verify_claims(policy)
            .map_err(|e| invalid(e.to_string()))?;
        proven.push(proof);
    }
    Ok(proven)
}

/// Build a Nonce Response (§7.2) around a fresh, unpredictable `c_nonce`
/// generated by the caller. Serve it with `Cache-Control: no-store`.
pub fn create_nonce_response(c_nonce: impl Into<String>) -> NonceResponse {
    NonceResponse {
        c_nonce: c_nonce.into(),
    }
}

/// Check a Notification Request (§11.1) against the `notification_id`s this
/// access token received (`invalid_notification_id` otherwise, §11.3).
pub fn check_notification_request(
    request: &NotificationRequest,
    is_known_notification_id: impl FnOnce(&str) -> bool,
) -> std::result::Result<(), NotificationErrorResponse> {
    if let NotificationEvent::Other(e) = &request.event {
        return Err(NotificationErrorResponse::new(
            NotificationErrorCode::InvalidNotificationRequest,
        )
        .with_description(format!("unknown event `{e}`")));
    }
    if !is_known_notification_id(&request.notification_id) {
        return Err(NotificationErrorResponse::new(
            NotificationErrorCode::InvalidNotificationId,
        ));
    }
    Ok(())
}
