//! Authorization Process
//! 1. Client gets a random challenge from the server
//! 2. Client encrypts the random challenge in a message and sends it back to the server POST /authenticate
//! 3. Server decrypts the message and verifies the challenge
//! 4. If the challenge is correct, the server sends two JWT tokens to the client (access and refresh tokens)
//! 5. Client uses the access token to access protected services
//! 6. If the access token expires, the client uses the refresh token to get a new access token

use super::message_inbound::InboundMessage;
use crate::{
    SharedData,
    common::acl_checks::ACLCheck,
    database::session::{Session, SessionClaims, SessionState},
};
use affinidi_messaging_didcomm::{Message, UnpackOptions, envelope::MetaEnvelope};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::{AuthorizationResponse, GenericDataStruct, known::MessageType},
    protocols::mediator::{accounts::AccountType, acls::MediatorACLSet},
};
use axum::{Json, extract::State};
use http::StatusCode;
use jsonwebtoken::{EncodingKey, Header, Validation, encode};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use sha256::digest;
use std::time::SystemTime;
use tracing::{Instrument, Level, debug, info, span, warn};
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
            return Err(MediatorError::ACLDenied("DID Blocked".to_string()).into());
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
                return Err(MediatorError::ParseError(
                    "UNKNOWN".to_string(),
                    "Raw inbound DIDComm message".into(),
                    e.to_string(),
                )
                .into());
            }
        };

        let from_did = match &envelope.from_did {
            Some(from_did) => {
                // Check if DID is allowed to connect
                if !MediatorACLSet::authentication_check(&state, &digest(from_did), None)
                    .await?
                    .0
                {
                    info!("DID({}) is blocked from connecting", from_did);
                    return Err(MediatorError::ACLDenied("DID Blocked".to_string()).into());
                }
                from_did.to_string()
            }
            _ => {
                return Err(MediatorError::AuthenticationError(
                    "Could not determine from_did".to_string(),
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
                return Err(MediatorError::MessageUnpackError(
                    "UNKNOWN".to_string(),
                    format!("Couldn't unpack incoming message. Reason: {}", e),
                )
                .into());
            }
        };

        // Only accepts AffinidiAuthenticate messages
        match msg.type_.as_str().parse::<MessageType>().map_err(|err| {
            MediatorError::ParseError("UNKNOWN".to_string(), "msg.type".into(), err.to_string())
        })? {
            MessageType::AffinidiAuthenticate => (),
            _ => {
                return Err(MediatorError::SessionError(
                    "UNKNOWN".to_string(),
                    "Only accepts Affinidi Authentication protocol messages".to_string(),
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
                return Err(MediatorError::MessageExpired(
                    "-1".into(),
                    expires.to_string(),
                    now.to_string(),
                )
                .into());
            }
        }

        // Turn message body into Challenge
        let challenge: AuthenticationChallenge =
            serde_json::from_value(msg.body).map_err(|err| {
                warn!(
                    "Couldn't parse body into AuthenticationChallenge. Reason: {}",
                    err
                );
                MediatorError::SessionError(
                    "UNKNOWN".into(),
                    format!(
                        "Couldn't parse body into AuthenticationChallenge. Reason: {}",
                        err
                    ),
                )
            })?;

        // Retrieve the session info from the database
        let mut session = state
            .database
            .get_session(&challenge.session_id, &from_did)
            .await?;

        // check that the DID matches from what was given for the initial challenge request to what was used for the message response
        if let Some(from_did) = msg.from {
            if from_did != session.did {
                warn!(
                    "DID ({}) from authorization message does not match DID ({}) from session",
                    from_did, session.did
                );
                return Err(MediatorError::SessionError(
                    challenge.session_id.clone(),
                    format!(
                        "DID ({}) from authorization message does not match DID from session",
                        from_did
                    ),
                )
                .into());
            }
        }

        // Check that this isn't a replay attack
        if let SessionState::ChallengeSent = session.state {
            debug!("Database session state is ChallengeSent - Good to go!");
        } else {
            warn!(
                "{}: Session is in an invalid state for authentication",
                session.session_id
            );
            return Err(MediatorError::SessionError(
                session.session_id.clone(),
                "Session is in an invalid state for authentication".into(),
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
                MediatorError::InternalError(
                    "UNKNOWN".into(),
                    format!("Couldn't encode refresh token. Reason: {}", err),
                )
            })?,
            refresh_expires_at: refresh_claims.exp,
        };

        // Set the session state to Authorized
        state
            .database
            .update_session_authenticated(&old_sid, &session.session_id, &digest(&session.did))
            .await?;

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
                return Err(MediatorError::ParseError(
                    "UNKNOWN".to_string(),
                    "Raw inbound DIDComm message".into(),
                    e.to_string(),
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
                return Err(MediatorError::MessageUnpackError(
                    "UNKNOWN".to_string(),
                    format!(
                        "Couldn't unpack incoming authentication refresh message. Reason: {}",
                        e
                    ),
                )
                .into());
            }
        };

        // Only accepts AffinidiAuthenticateRefresh messages
        match msg.type_.as_str().parse::<MessageType>().map_err(|err| {
            MediatorError::ParseError("UNKNOWN".to_string(), "msg.type".into(), err.to_string())
        })? {
            MessageType::AffinidiAuthenticateRefresh => (),
            _ => {
                return Err(MediatorError::SessionError(
                    "UNKNOWN".to_string(),
                    "Only accepts Affinidi Authentication protocol messages".to_string(),
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
                return Err(MediatorError::MessageExpired(
                    "-1".into(),
                    expires.to_string(),
                    now.to_string(),
                )
                .into());
            }
        }

        let refresh_token = if let Some(refresh_token) = msg.body.get("refresh_token") {
            if let Some(refresh_token) = refresh_token.as_str() {
                refresh_token
            } else {
                return Err(MediatorError::ParseError(
                    "UNKNOWN".into(),
                    "msg.body".into(),
                    "Couldn't parse message body into refresh_token".into(),
                )
                .into());
            }
        } else {
            return Err(MediatorError::ParseError(
                "UNKNOWN".into(),
                "msg.body".into(),
                "Couldn't parse message body into refresh_token".into(),
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
                return Err(MediatorError::AuthenticationError(format!(
                    "Couldn't decode refresh token. Reason: {}",
                    err
                ))
                .into());
            }
        };

        // Refresh token is valid - check against database and ensure it still exists
        let session_check = match &envelope.from_did {
            Some(from_did) => {
                state
                    .database
                    .get_session(&results.claims.session_id, from_did)
                    .await?
            }
            _ => {
                return Err(MediatorError::AuthenticationError(
                    "Could not determine from_did".to_string(),
                )
                .into());
            }
        };

        // Is the session in an authenticated state? If not, then we can't refresh
        if session_check.state != SessionState::Authenticated {
            return Err(MediatorError::SessionError(
                results.claims.session_id.clone(),
                "Session is not in an authenticated state".into(),
            )
            .into());
        }

        // Does the Global ACL still allow them to connect?
        if session_check.acls.get_blocked() {
            info!("DID({}) is blocked from connecting", session_check.did);
            return Err(MediatorError::ACLDenied("DID Blocked".to_string()).into());
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
        MediatorError::InternalError(
            "UNKNOWN".into(),
            format!("Couldn't encode access token. Reason: {}", err),
        )
    })?;

    Ok((access_token, access_claims.exp))
}
