//! Authorization Process
//! 1. Client gets a random challenge from the server
//! 2. Client encrypts the random challenge in a message and sends it back to the server POST /authenticate
//! 3. Server decrypts the message and verifies the challenge
//! 4. If the challenge is correct, the server sends two JWT tokens to the client (access and refresh tokens)
//! 5. Client uses the access token to access protected services
//! 6. If the access token expires, the client uses the refresh token to get a new access token
//!
//! NOTE: All errors handled in the handlers are returned as a Problem Report messages

use super::message_inbound::InboundMessage;
use crate::{
    SharedData,
    common::acl_checks::ACLCheck,
    database::session::{Session, SessionClaims, SessionState},
};
use affinidi_messaging_didcomm::{Message, UnpackOptions, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::{
        AuthorizationResponse, GenericDataStruct,
        known::MessageType,
        problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
    },
    protocols::mediator::{accounts::AccountType, acls::MediatorACLSet},
};
use axum::{Json, extract::State};
use http::StatusCode;
use jsonwebtoken::{EncodingKey, Header, Validation, encode};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::time::SystemTime;
use tracing::{Instrument, Level, debug, info, span};
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthenticationChallenge {
    pub challenge: String,
    pub session_id: String,
}
impl GenericDataStruct for AuthenticationChallenge {}

/// Refresh tokens response from the authentication service
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct AuthRefreshResponse {
    pub access_token: String,
    pub access_expires_at: u64,
}
impl GenericDataStruct for AuthRefreshResponse {}

/// Request body for POST /authenticate/challenge
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ChallengeBody {
    pub did: String,
}

/// POST /authenticate/challenge
/// Request from client to get the challenge
/// This is the first step in the authentication process
/// Creates a new sessionID and a random challenge string to the client
pub async fn authentication_challenge(
    State(state): State<SharedData>,
    Json(body): Json<ChallengeBody>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthenticationChallenge>>), AppError> {
    let session = Session {
        session_id: create_random_string(12),
        challenge: create_random_string(32),
        state: SessionState::ChallengeSent,
        did: body.did.clone(),
        did_hash: digest(body.did),
        authenticated: false,
        acls: MediatorACLSet::default(), // this will be updated later
        account_type: AccountType::Standard,
        expires_at: 0,
    };
    let _span = span!(
        Level::DEBUG,
        "authentication_challenge",
        session_id = session.session_id,
        did_hash = session.did_hash.clone()
    );
    async move {
        // ACL Checks to be done
        // 1. Do we know this DID?
        //   1.1 If yes, then is it blocked?
        // 2. If not known, then does the mediator acl_mode allow for new accounts?
        // 3. If yes, then add the account and continue

        // Check if DID is allowed to connect
        let (allowed, known) =
            MediatorACLSet::authentication_check(&state, &session.did_hash, None).await?;

        if !allowed {
            info!("DID({}) is blocked from connecting", session.did);
            return Err(MediatorError::MediatorError(
                25,
                session.session_id,
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.blocked".into(),
                    "DID is blocked".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "DID is blocked".to_string(),
            )
            .into());
        } else if !known {
            // Register the DID as a local DID
            state
                .database
                .account_add(
                    &session.did_hash,
                    &state.config.security.global_acl_default,
                    None,
                )
                .await?;
        }

        state.database.create_session(&session).await?;

        debug!(
            "{}: Challenge sent to DID({})",
            session.session_id, session.did
        );

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id.clone(),
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthenticationChallenge {
                    challenge: session.challenge,
                    session_id: session.session_id.clone(),
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}

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
        let s = serde_json::to_string(&body).unwrap();

        let mut envelope = match MetaEnvelope::new(&s, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    28,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.response.parse".into(),
                        "authentication response couldn't be parsed: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("authentication response couldn't be parsed: {e}"),
                )
                .into());
            }
        };

        // Authentication messages MUST be signed and authenticated!
        if envelope.metadata.authenticated && envelope.metadata.encrypted {
            debug!("Authenticated messages is properly signed and encrypted")
        } else {
                return Err(MediatorError::MediatorError(
                    86,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.message.not_signed_or_encrypted".into(),
                        "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction".into(),
                        vec![envelope.metadata.authenticated.to_string(), envelope.metadata.encrypted.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction", envelope.metadata.authenticated, envelope.metadata.encrypted)
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
                            return Err(MediatorError::MediatorError(
                                25,
                                "".to_string(),
                                None,
                                Box::new(ProblemReport::new(
                                    ProblemReportSorter::Error,
                                    ProblemReportScope::Protocol,
                                    "authentication.blocked".into(),
                                    "DID is blocked".into(),
                                    vec![],
                                    None,
                                )),
                                StatusCode::FORBIDDEN.as_u16(),
                                "DID is blocked".to_string(),
                            )
                            .into());
                        }
                    }
                    Err(e) => {
                        return Err(MediatorError::MediatorError(
                            14,
                            "".to_string(),
                            None,
                            Box::new(ProblemReport::new(
                                ProblemReportSorter::Error,
                                ProblemReportScope::Protocol,
                                "me.res.storage.error".into(),
                                "Database transaction error: {1}".into(),
                                vec![e.to_string()],
                                None,
                            )),
                            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                            format!("Database transaction error: {e}"),
                        )
                        .into());
                    }
                }
            }
            _ => {
                return Err(MediatorError::MediatorError(
                    29,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.response.from".into(),
                        "Authentication response message is missing the `from` header".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Authentication response message is missing the `from` header".to_string(),
                )
                .into());
            }
        };

        // Unpack the message
        let (msg, _) = match Message::unpack(
            &mut envelope,
            &state.did_resolver,
            &*state.config.security.mediator_secrets,
            &UnpackOptions::default(),
        )
        .await
        {
            Ok(ok) => ok,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    32,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.unpack".into(),
                        "Message unpack failed: envelope {1} Reason: {2}".into(),
                        vec![s, e.to_string()],
                        None,
                    )),
                    StatusCode::FORBIDDEN.as_u16(),
                    format!("Message unpack failed. Reason: {e}"),
                )
                .into());
            }
        };

        // Authentication messages MUST be signed and authenticated!
        if envelope.metadata.authenticated && envelope.metadata.encrypted && envelope.metadata.non_repudiation {
            debug!("Authentication message is properly signed and encrypted")
        } else {
                return Err(MediatorError::MediatorError(
                    86,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.message.not_signed_or_encrypted".into(),
                        "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction".into(),
                        vec![envelope.metadata.authenticated.to_string(), envelope.metadata.encrypted.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction", envelope.metadata.authenticated, envelope.metadata.encrypted)
                )
                .into());
        }

        // Check that the inner plaintext from matches the envelope skid
        if let Some(msg_from) = &msg.from {
            if msg_from != envelope.from_did.as_ref().unwrap_or(&String::new()) {
                // Inner and outer envelope don't match
            return Err(MediatorError::MediatorError(
                85,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.from.incorrect".into(),
                    "Inner DIDComm plaintext from field does NOT match signing or encryption DID".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Inner DIDComm plaintext from field does NOT match signing or encryption DID".to_string(),
            )
            .into());
            }
        } else {
            return Err(MediatorError::MediatorError(
                29,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.response.from".into(),
                    "inner message: Missing the `from` header".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "inner message: Missing the `from` header".to_string(),
            )
            .into());
        }

        // Check that the inner plaintext from matches the envelope skid
        if let Some(msg_from) = &msg.from {
            if msg_from != envelope.from_did.as_ref().unwrap_or(&String::new()) {
                // Inner and outer envelope don't match
            return Err(MediatorError::MediatorError(
                85,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.from.incorrect".into(),
                    "Inner DIDComm plaintext from field does NOT match signing or encryption DID".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Inner DIDComm plaintext from field does NOT match signing or encryption DID".to_string(),
            )
            .into());
            }
        } else {
            return Err(MediatorError::MediatorError(
                29,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.response.from".into(),
                    "inner message: Missing the `from` header".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "inner message: Missing the `from` header".to_string(),
            )
            .into());
        }

        // Only accepts AffinidiAuthenticate messages
        match msg.type_.as_str().parse::<MessageType>().map_err(|err| {
            MediatorError::MediatorError(
                30,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.type.incorrect".into(),
                    "Unexpected message type: {1}: Error: {2}".into(),
                    vec![msg.type_.to_string(), err.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("Unexpected message type: {} Error: {}", msg.type_, err),
            )
        })? {
            MessageType::AffinidiAuthenticate => (),
            _ => {
                return Err(MediatorError::MediatorError(
                    30,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.type.incorrect".into(),
                        "Unexpected message type: {1}".into(),
                        vec![msg.type_.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Unexpected message type: {}", msg.type_),
                )
                .into());
            }
        }

        // Ensure the message hasn't expired
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(expires) = msg.expires_time {
            if expires <= now {
                return Err(MediatorError::MediatorError(
                    31,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.expired".into(),
                        "Message has expired: {1}".into(),
                        vec![expires.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Message has expired".to_string(),
                )
                .into());
            }
        } else {
            // Authentication responses must have an expires_time header
            return Err(MediatorError::MediatorError(
                31,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.expired".into(),
                    "Message is missing the expires_time header. Must contain this header".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Message missing expires_time header".to_string(),
            )
            .into());
        }

        // Turn message body into Challenge response
        let challenge: AuthenticationChallenge = serde_json::from_value(msg.body).map_err(|e| {
            MediatorError::MediatorError(
                28,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.response.parse".into(),
                    "authentication response couldn't be parsed: {1}".into(),
                    vec![e.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
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
                return Err(MediatorError::MediatorError(
                    14,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.error".into(),
                        "Database transaction error: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    format!("Database transaction error: {e}"),
                )
                .into());
            }
        };

        // check that the DID matches from what was given for the initial challenge request to what was used for the message response
        if let Some(from_did) = &msg.from && from_did != &session.did {
                return Err(MediatorError::MediatorError(
                    33,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.session.mismatch".into(),
                        "DID mismatch during authentication process".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
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
            return Err(MediatorError::MediatorError(
                34,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.invalid".into(),
                    "Session is in an invalid state to complete authentication".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Session is in an invalid state to complete authentication".to_string(),
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

        let refresh_claims = SessionClaims {
            aud: "ATM".to_string(),
            sub: session.did.clone(),
            session_id: session.session_id.clone(),
            exp: (SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + (state.config.security.jwt_refresh_expiry
                    - state.config.security.jwt_access_expiry)),
        };

        session.expires_at = access_expires_at;

        let response = AuthorizationResponse {
            access_token,
            access_expires_at,
            refresh_token: encode(
                &Header::new(jsonwebtoken::Algorithm::EdDSA),
                &refresh_claims,
                &state.config.security.jwt_encoding_key,
            )
            .map_err(|err| {
                MediatorError::MediatorError(
                    36,
                    session.session_id.to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.session.refresh_token".into(),
                        "Couldn't create JWT Refresh token. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!("Couldn't create JWT Refresh token. Reason: {err}"),
                )
            })?,
            refresh_expires_at: refresh_claims.exp,
        };

        // Set the session state to Authorized
        state
            .database
            .update_session_authenticated(&old_sid, &session.session_id, &digest(&session.did))
            .await
            .map_err(|e| {
                MediatorError::MediatorError(
                    14,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "me.res.storage.error".into(),
                        "Database transaction error: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                    format!("Database transaction error: {e}"),
                )
            })?;

        // Register the DID and initial setup
        _register_did_and_setup(&state, &session.did_hash).await?;

        info!(
            "{}: Authentication successful for DID({})",
            session.session_id, session.did
        );

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id.clone(),
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
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
        let s = serde_json::to_string(&body).unwrap();

        let mut envelope = match MetaEnvelope::new(&s, &state.did_resolver).await {
            Ok(envelope) => envelope,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    37,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.envelope.read".into(),
                        "Couldn't read DIDComm envelope: {1}".into(),
                        vec![e.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Couldn't read DIDComm envelope: {e}"),
                )
                .into());
            }
        };

        // Unpack the message
        let (msg, _) = match Message::unpack(
            &mut envelope,
            &state.did_resolver,
            &*state.config.security.mediator_secrets,
            &UnpackOptions::default(),
        )
        .await
        {
            Ok(ok) => ok,
            Err(e) => {
                return Err(MediatorError::MediatorError(
                    32,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.unpack".into(),
                        "Message unpack failed: envelope {1} Reason: {2}".into(),
                        vec![s, e.to_string()],
                        None,
                    )),
                    StatusCode::FORBIDDEN.as_u16(),
                    format!("Message unpack failed. Reason: {e}"),
                )
                .into());
            }
        };

        // Authentication messages MUST be signed and authenticated!
        if envelope.metadata.authenticated && envelope.metadata.encrypted && envelope.metadata.non_repudiation {
            debug!("Authentication message is properly signed and encrypted")
        } else {
                return Err(MediatorError::MediatorError(
                    86,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.message.not_signed_or_encrypted".into(),
                        "DIDComm message MUST be signed ({1}) and encrypted ({2}) for this transaction".into(),
                        vec![envelope.metadata.authenticated.to_string(), envelope.metadata.encrypted.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("DIDComm message MUST be signed ({}) and encrypted ({}) for this transaction", envelope.metadata.authenticated, envelope.metadata.encrypted)
                )
                .into());
        }

        // Only accepts AffinidiAuthenticateRefresh messages
        match msg.type_.as_str().parse::<MessageType>().map_err(|err| {
            MediatorError::MediatorError(
                30,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.type.incorrect".into(),
                    "Unexpected message type: {1}: Error: {2}".into(),
                    vec![msg.type_.to_string(), err.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("Unexpected message type: {} Error: {}", msg.type_, err),
            )
        })? {
            MessageType::AffinidiAuthenticateRefresh => (),
            _ => {
                return Err(MediatorError::MediatorError(
                    30,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.type.incorrect".into(),
                        "Unexpected message type: {1}".into(),
                        vec![msg.type_.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("Unexpected message type: {}", msg.type_),
                )
                .into());
            }
        }

        // Ensure the message hasn't expired
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if let Some(expires) = msg.expires_time {
            if expires <= now {
                return Err(MediatorError::MediatorError(
                    31,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "message.expired".into(),
                        "Message has expired: {1}".into(),
                        vec![expires.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    "Message has expired".to_string(),
                )
                .into());
            }
        } else {
            // Authentication responses must have an expires_time header
            return Err(MediatorError::MediatorError(
                31,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "message.expired".into(),
                    "Message is missing the expires_time header. Must contain this header".into(),
                    vec![],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Message missing expires_time header".to_string(),
            )
            .into());
        }

        let refresh_token = if let Some(refresh_token) = msg.body.get("refresh_token") {
            if let Some(refresh_token) = refresh_token.as_str() {
                refresh_token
            } else {
                return Err(MediatorError::MediatorError(
                    38,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.session.refresh_token.parse".into(),
                        "Couldn't parse JWT Refresh token. Not a string.".into(),
                        vec![],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    "Couldn't create JWT Refresh token. Not a string".to_string(),
                )
                .into());
            }
        } else {
            return Err(MediatorError::MediatorError(
                38,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.refresh_token.parse".into(),
                    "Couldn't parse JWT Refresh token. Missing.".into(),
                    vec![],
                    None,
                )),
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "Couldn't parse JWT Refresh token. Missing".to_string(),
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
                return Err(MediatorError::MediatorError(
                    38,
                    "".to_string(),
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "authentication.session.refresh_token.parse".into(),
                        "Couldn't decode JWT Refresh token. Reason: {1}".into(),
                        vec![err.to_string()],
                        None,
                    )),
                    StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                    format!("Couldn't decode JWT Refresh token. Reason: {err}"),
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
                    MediatorError::MediatorError(
                        14,
                        "".to_string(),
                        None,
                        Box::new(ProblemReport::new(
                            ProblemReportSorter::Error,
                            ProblemReportScope::Protocol,
                            "me.res.storage.error".into(),
                            "Database transaction error: {1}".into(),
                            vec![e.to_string()],
                            None,
                        )),
                        StatusCode::SERVICE_UNAVAILABLE.as_u16(),
                        format!("Database transaction error: {e}"),
                    )
                })?
        } else {
            return Err(MediatorError::MediatorError(
                39,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.message.from.missing".into(),
                    "DIDComm message is missing the from: header. Required for this transaction"
                        .into(),
                    vec![],
                    None,
                )),
                StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                "DIDComm message is missing the from: header. Required for this transaction"
                    .to_string(),
            )
            .into());
        };

        // Is the session in an authenticated state? If not, then we can't refresh
        if session_check.state != SessionState::Authenticated {
            return Err(MediatorError::MediatorError(
                34,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.session.invalid".into(),
                    "Session is in an invalid state to complete authentication. Should be Authenticated, instead is {1}".into(),
                    vec![session_check.state.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                format!("Session is in an invalid state to complete authentication. Should be Authenticated, instead is {}", session_check.state),
            )
            .into());
        }

        // Does the Global ACL still allow them to connect?
        if session_check.acls.get_blocked() {
            info!("DID({}) is blocked from connecting", session_check.did);
            return Err(MediatorError::MediatorError(
                25,
                "".to_string(),
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.blocked".into(),
                    "DID is blocked".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "DID is blocked".to_string(),
            )
            .into());
        }

        // Generate a new access token
        let (access_token, access_expires_at) = _create_access_token(
            &session_check.did,
            &session_check.session_id,
            state.config.security.jwt_access_expiry,
            &state.config.security.jwt_encoding_key,
        )?;

        info!(
            "{}: Access JWT refreshed for DID({})",
            session_check.session_id,
            digest(session_check.did)
        );

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session_check.session_id.clone(),
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthRefreshResponse {
                    access_token,
                    access_expires_at,
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// creates a random string of up to length characters
fn create_random_string(length: usize) -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

fn _create_access_token(
    did: &str,
    session_id: &str,
    expiry: u64,
    encoding_key: &EncodingKey,
) -> Result<(String, u64), MediatorError> {
    // Passed all the checks, now create the JWT tokens
    let access_claims = SessionClaims {
        aud: "ATM".to_string(),
        sub: did.to_owned(),
        session_id: session_id.to_owned(),
        exp: (SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expiry),
    };

    let access_token = encode(
        &Header::new(jsonwebtoken::Algorithm::EdDSA),
        &access_claims,
        encoding_key,
    )
    .map_err(|err| {
        MediatorError::MediatorError(
            35,
            session_id.to_string(),
            None,
            Box::new(ProblemReport::new(
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.access_token".into(),
                "Couldn't create JWT Access token. Reason: {1}".into(),
                vec![err.to_string()],
                None,
            )),
            StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            format!("Couldn't create JWT Access token. Reason: {err}"),
        )
    })?;

    Ok((access_token, access_claims.exp))
}
