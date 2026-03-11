use super::helpers::{_create_access_token, _create_refresh_token};
use super::AuthRefreshResponse;
use crate::{
    SharedData,
    database::session::{SessionClaims, SessionState},
};
use super::super::message_inbound::InboundMessage;
use crate::didcomm_compat::{self, MetaEnvelope};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    known::MessageType,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use jsonwebtoken::Validation;
use sha256::digest;
use subtle::ConstantTimeEq;
use crate::common::time::unix_timestamp_secs;
use tracing::{Instrument, Level, debug, info, span};

/// POST /authenticate/refresh
/// Refresh existing JWT tokens.
/// Initiated by the client when they notice JWT is expiring
/// Provide their refresh token, and if still valid then we issue a new access token
pub async fn authentication_refresh(
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthRefreshResponse>>), AppError> {
    let _span = span!(Level::DEBUG, "authentication_refresh",);

    async move {
        let s = serde_json::to_string(&body).map_err(|e| {
            MediatorError::problem_with_log(
                37, "", None,
                ProblemReportSorter::Error, ProblemReportScope::Protocol,
                "message.serialize", "Failed to serialize request body: {1}",
                vec![e.to_string()], StatusCode::BAD_REQUEST,
                format!("Failed to serialize request body: {e}"),
            )
        })?;

        let mut envelope = match MetaEnvelope::new(&s, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    37,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.envelope.read",
                    "Couldn't read DIDComm envelope: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Couldn't read DIDComm envelope: {e}"),
                )
                .into());
            }
        };

        // Unpack the message
        let (msg, unpack_metadata) = match didcomm_compat::unpack(
            &s,
            &state.did_resolver,
            &*state.config.security.mediator_secrets,
        )
        .await
        {
            Ok(ok) => ok,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    32,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.unpack",
                    "Failed to unpack message. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::FORBIDDEN,
                    format!("Failed to unpack message. Reason: {e}"),
                )
                .into());
            }
        };

        // Authentication messages MUST be signed and authenticated!
        if unpack_metadata.authenticated && unpack_metadata.encrypted {
            debug!("Authentication message is properly signed and encrypted")
        } else {
                return Err(MediatorError::problem_with_log(
                    86,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.message.not_signed_or_encrypted",
                    "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction",
                    vec![unpack_metadata.authenticated.to_string(), unpack_metadata.encrypted.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction", unpack_metadata.authenticated, unpack_metadata.encrypted),
                )
                .into());
        }

        // Only accepts AffinidiAuthenticateRefresh messages
        match msg.typ.as_str().parse::<MessageType>().map_err(|err| {
            MediatorError::problem_with_log(
                30,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.type.incorrect",
                "Unexpected message type: {1}. Reason: {2}",
                vec![msg.typ.to_string(), err.to_string()],
                StatusCode::BAD_REQUEST,
                format!("Unexpected message type: {}. Reason: {}", msg.typ, err),
            )
        })? {
            MessageType::AffinidiAuthenticateRefresh => (),
            _ => {
                return Err(MediatorError::problem_with_log(
                    30,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.type.incorrect",
                    "Unexpected message type: {1}",
                    vec![msg.typ.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Unexpected message type: {}", msg.typ),
                )
                .into());
            }
        }

        // Ensure the message hasn't expired
        let now = unix_timestamp_secs();
        if let Some(expires) = msg.expires_time {
            if expires <= now {
                return Err(MediatorError::problem_with_log(
                    31,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.expired",
                    "Message has expired: {1}",
                    vec![expires.to_string()],
                    StatusCode::BAD_REQUEST,
                    "Message has expired",
                )
                .into());
            }
        } else {
            // Authentication responses must have an expires_time header
            return Err(MediatorError::problem(
                92,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.expires_time.missing",
                "Authentication messages must include an expires_time header",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }

        let refresh_token = if let Some(refresh_token) = msg.body.get("refresh_token") {
            if let Some(refresh_token) = refresh_token.as_str() {
                refresh_token
            } else {
                return Err(MediatorError::problem_with_log(
                    38,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.refresh_token.parse",
                    "Failed to parse JWT refresh token: not a string",
                    vec![],
                    StatusCode::BAD_REQUEST,
                    "Failed to parse JWT refresh token: not a string",
                )
                .into());
            }
        } else {
            return Err(MediatorError::problem_with_log(
                38,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.refresh_token.parse",
                "Failed to parse JWT refresh token: missing",
                vec![],
                StatusCode::BAD_REQUEST,
                "Failed to parse JWT refresh token: missing",
            )
            .into());
        };

        // Decode the refresh token
        let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id"]);
        let results = match jsonwebtoken::decode::<SessionClaims>(
            refresh_token,
            &state.config.security.jwt_decoding_key,
            &validation,
        ) {
            Ok(token) => token,
            Err(err) => {
                return Err(MediatorError::problem_with_log(
                    38,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.refresh_token.parse",
                    "Failed to decode JWT refresh token. Reason: {1}",
                    vec![err.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("Failed to decode JWT refresh token. Reason: {err}"),
                )
                .into());
            }
        };

        // Refresh token is valid - check against database and ensure it still exists
        let session_check = if let Some(from_did) = &envelope.from_did {
            state
                .database
                .get_session(&results.claims.session_id, from_did)
                .await
                .map_err(|e| {
                    MediatorError::problem_with_log(
                        14,
                        "",
                        None,
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.error",
                        "Database transaction error: {1}",
                        vec![e.to_string()],
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("Database transaction error: {e}"),
                    )
                })?
        } else {
            return Err(MediatorError::problem(
                39,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.message.from.missing",
                "DIDComm message is missing the from: header. Required for this transaction",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        };

        // Is the session in an authenticated state? If not, then we can't refresh
        if session_check.state != SessionState::Authenticated {
            return Err(MediatorError::problem_with_log(
                34,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.invalid",
                "Session is in an invalid state to complete authentication. Should be Authenticated, instead is {1}",
                vec![session_check.state.to_string()],
                StatusCode::BAD_REQUEST,
                format!("Session is in an invalid state to complete authentication. Should be Authenticated, instead is {}", session_check.state),
            )
            .into());
        }

        // Does the Global ACL still allow them to connect?
        if session_check.acls.get_blocked() {
            info!("DID({}) is blocked from connecting", digest(&session_check.did));
            return Err(MediatorError::problem(
                25,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.blocked",
                "DID is blocked",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        // Validate refresh token is one-time use by checking stored hash
        let incoming_hash = digest(refresh_token);
        let stored_hash = state
            .database
            .get_refresh_token_hash(&session_check.session_id)
            .await
            .map_err(|e| {
                MediatorError::problem_with_log(
                    14,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.error",
                    "Database transaction error: {1}",
                    vec![e.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Database transaction error: {e}"),
                )
            })?;

        if let Some(stored) = stored_hash {
            if !bool::from(stored.as_bytes().ct_eq(incoming_hash.as_bytes())) {
                metrics::counter!(crate::common::metrics::names::AUTH_FAILURES_TOTAL, "reason" => "refresh_token_reuse").increment(1);
                return Err(MediatorError::problem_with_log(
                    38,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.refresh_token.reuse",
                    "Refresh token has already been used (possible token replay)",
                    vec![],
                    StatusCode::UNAUTHORIZED,
                    "Refresh token has already been used (possible token replay)",
                )
                .into());
            }
        }

        // Generate a new access token
        let (access_token, access_expires_at) = _create_access_token(
            &session_check.did,
            &session_check.session_id,
            state.config.security.jwt_access_expiry,
            &state.config.security.jwt_encoding_key,
        )?;

        // Generate a new refresh token (rotation — old one is now invalid)
        let refresh_expiry = state.config.security.jwt_refresh_expiry
            - state.config.security.jwt_access_expiry;
        let (new_refresh_token, new_refresh_expires_at, new_refresh_hash) = _create_refresh_token(
            &session_check.did,
            &session_check.session_id,
            refresh_expiry,
            &state.config.security.jwt_encoding_key,
        )?;

        // Store the new refresh token hash
        state
            .database
            .update_refresh_token_hash(&session_check.session_id, &new_refresh_hash)
            .await
            .map_err(|e| {
                MediatorError::problem_with_log(
                    14,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "me.res.storage.error",
                    "Database transaction error: {1}",
                    vec![e.to_string()],
                    StatusCode::SERVICE_UNAVAILABLE,
                    format!("Database transaction error: {e}"),
                )
            })?;

        metrics::counter!(crate::common::metrics::names::AUTH_REFRESH_TOTAL).increment(1);
        info!(
            "{}: JWT tokens refreshed for DID({})",
            session_check.session_id,
            digest(&session_check.did)
        );

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session_check.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthRefreshResponse {
                    access_token,
                    access_expires_at,
                    refresh_token: new_refresh_token,
                    refresh_expires_at: new_refresh_expires_at,
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}
