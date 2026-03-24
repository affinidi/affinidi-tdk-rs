use super::super::message_inbound::InboundMessage;
use super::AuthenticationChallenge;
use super::helpers::{_create_access_token, _create_refresh_token, create_random_string};
use crate::common::time::unix_timestamp_secs;
use crate::didcomm_compat::{self, MetaEnvelope};
use crate::{SharedData, common::acl_checks::ACLCheck, database::session::SessionState};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::{
        AuthorizationResponse,
        known::MessageType,
        problem_report::{ProblemReportScope, ProblemReportSorter},
    },
    protocols::mediator::acls::MediatorACLSet,
};
use axum::{Json, extract::State};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, Level, debug, info, span};

/// POST /authenticate
/// Response from client to the challenge
/// Unpack the message (only accepts Affinidi Authenticate Protocol)
/// Retrieve Session data from database
/// Check that the DID matches from the message to the session DID recorded
pub async fn authentication_response(
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthorizationResponse>>), AppError> {
    let _span = span!(Level::DEBUG, "authentication_response",);

    async move {
        let s = serde_json::to_string(&body).map_err(|e| {
            MediatorError::problem_with_log(
                37,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "message.serialize",
                "Failed to serialize request body: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
                format!("Failed to serialize request body: {e}"),
            )
        })?;

        let envelope = match MetaEnvelope::new(&s, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    28,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.response.parse",
                    "authentication response couldn't be parsed: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    format!("authentication response couldn't be parsed: {e}"),
                )
                .into());
            }
        };

        // Authentication messages MUST be signed and authenticated!
        if envelope.metadata.authenticated && envelope.metadata.encrypted {
            debug!("Authenticated messages is properly signed and encrypted")
        } else {
            return Err(MediatorError::problem_with_log(
                86,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.message.not_signed_or_encrypted",
                "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction",
                vec![
                    envelope.metadata.authenticated.to_string(),
                    envelope.metadata.encrypted.to_string(),
                ],
                StatusCode::BAD_REQUEST,
                format!(
                    "DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction",
                    envelope.metadata.authenticated, envelope.metadata.encrypted
                ),
            )
            .into());
        }

        let from_did = match &envelope.from_did {
            Some(from_did) => {
                // Check if DID is allowed to connect
                match MediatorACLSet::authentication_check(&state, &digest(from_did), None).await {
                    Ok((allowed, _)) => {
                        if allowed {
                            from_did.to_string()
                        } else {
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
                    }
                    Err(e) => {
                        return Err(MediatorError::problem_with_log(
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
                        .into());
                    }
                }
            }
            _ => {
                return Err(MediatorError::problem(
                    29,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.response.from",
                    "Authentication response message is missing the `from` header",
                    vec![],
                    StatusCode::BAD_REQUEST,
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
                vec![
                    unpack_metadata.authenticated.to_string(),
                    unpack_metadata.encrypted.to_string(),
                ],
                StatusCode::BAD_REQUEST,
                format!(
                    "DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction",
                    unpack_metadata.authenticated, unpack_metadata.encrypted
                ),
            )
            .into());
        }

        // Check that the inner plaintext from matches the envelope skid
        if let Some(msg_from) = &msg.from {
            if msg_from != envelope.from_did.as_ref().unwrap_or(&String::new()) {
                // Inner and outer envelope don't match
                return Err(MediatorError::problem(
                    85,
                    "",
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.from.incorrect",
                    "Inner DIDComm plaintext from field does NOT match signing or encryption DID",
                    vec![],
                    StatusCode::BAD_REQUEST,
                )
                .into());
            }
        } else {
            return Err(MediatorError::problem(
                29,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.response.from",
                "inner message: Missing the `from` header",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }

        // Only accepts AffinidiAuthenticate messages
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
            MessageType::AffinidiAuthenticate => (),
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

        // Turn message body into Challenge response
        let challenge: AuthenticationChallenge = serde_json::from_value(msg.body).map_err(|e| {
            MediatorError::problem_with_log(
                28,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.response.parse",
                "authentication response couldn't be parsed: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
                format!("authentication response couldn't be parsed: {e}"),
            )
        })?;

        // Retrieve the session info from the database
        let mut session = match state
            .database
            .get_session(&challenge.session_id, &from_did)
            .await
        {
            Ok(session) => session,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
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
                .into());
            }
        };

        // check that the DID matches from what was given for the initial challenge request to what was used for the message response
        if let Some(from_did) = &msg.from
            && from_did != &session.did
        {
            return Err(MediatorError::problem_with_log(
                33,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.mismatch",
                "DID mismatch during authentication process",
                vec![],
                StatusCode::BAD_REQUEST,
                format!(
                    "DID mismatch during authentication process: first_did({}) second_did({})",
                    session.did, from_did
                ),
            )
            .into());
        }

        // Check that this isn't a replay attack
        if let SessionState::ChallengeSent = session.state {
            debug!("Database session state is ChallengeSent - Good to go!");
        } else {
            return Err(MediatorError::problem(
                34,
                "",
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.invalid",
                "Session is in an invalid state to complete authentication",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }
        let old_sid = session.session_id;
        session.session_id = create_random_string(12);

        // Passed all the checks, now create the JWT tokens
        let (access_token, access_expires_at) = _create_access_token(
            &session.did,
            &session.session_id,
            state.config.security.jwt_access_expiry,
            &state.config.security.jwt_encoding_key,
        )?;

        let refresh_expiry =
            state.config.security.jwt_refresh_expiry - state.config.security.jwt_access_expiry;
        let (refresh_token, refresh_expires_at, refresh_token_hash) = _create_refresh_token(
            &session.did,
            &session.session_id,
            refresh_expiry,
            &state.config.security.jwt_encoding_key,
        )?;

        session.expires_at = access_expires_at;

        let response = AuthorizationResponse {
            access_token,
            access_expires_at,
            refresh_token,
            refresh_expires_at,
        };

        // Set the session state to Authorized and store refresh token hash
        state
            .database
            .update_session_authenticated(
                &old_sid,
                &session.session_id,
                &digest(&session.did),
                &refresh_token_hash,
            )
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

        // Register the DID and initial setup
        _register_did_and_setup(&state, &session.did_hash).await?;

        metrics::counter!(crate::common::metrics::names::AUTH_SUCCESS_TOTAL).increment(1);
        info!(
            "{}: Authentication successful for DID({})",
            session.session_id,
            digest(&session.did)
        );

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(response),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// Check if the DID is already registered and set up (as needed)
/// A DID is only registered if local accounts are enabled via ACL
async fn _register_did_and_setup(state: &SharedData, did_hash: &str) -> Result<(), MediatorError> {
    // Do we already know about this DID?
    if state.database.account_exists(did_hash).await? {
        debug!("DID({}) already registered", did_hash);
        return Ok(());
    } else if state.config.security.global_acl_default.get_local() {
        // Register the DID as a local DID
        state
            .database
            .account_add(did_hash, &state.config.security.global_acl_default, None)
            .await?;
    }

    Ok(())
}
