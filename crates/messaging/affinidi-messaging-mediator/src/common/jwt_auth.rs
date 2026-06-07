use crate::{
    SharedData,
    common::session::{Session, SessionClaims},
};
use affinidi_messaging_mediator_common::errors::ErrorResponse;
use axum::{
    Json, RequestPartsExt,
    extract::{FromRef, FromRequestParts},
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{StatusCode, request::Parts};
use jsonwebtoken::{TokenData, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha256::digest;
use std::{
    fmt::{Debug, Display},
    net::SocketAddr,
};
use tracing::{Level, debug, error, event, info, warn};

// Payload contents of the JWT
// All times are in seconds since UNIX EPOCH
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub aud: Vec<String>, // Intended Audience
    pub client_id: String,
    pub exp: u64,    // What does this JWT Expire
    pub iat: u64,    // Issued at this time
    pub iss: String, // Who issued this JWT?
    pub jti: String, // JWT ID
    pub nbf: u64,    // JWT is not valid before this time
    /// OAuth2 scopes (reserved for future use)
    pub scp: Vec<String>,
    pub sub: String, // subject - who this JWT refers to
}

#[derive(Debug)]
pub enum AuthError {
    WrongCredentials,
    MissingCredentials,
    InvalidToken,
    ExpiredToken,
    InternalServerError(String),
    Blocked,
}

impl Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::WrongCredentials => write!(f, "Wrong credentials"),
            AuthError::MissingCredentials => write!(f, "Missing credentials"),
            AuthError::InvalidToken => write!(f, "Invalid token"),
            AuthError::ExpiredToken => write!(f, "Expired token"),
            AuthError::InternalServerError(message) => {
                write!(f, "Internal Server Error: {message}")
            }
            AuthError::Blocked => write!(f, "ACL Blocked"),
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let status = match self {
            AuthError::WrongCredentials => StatusCode::UNAUTHORIZED,
            AuthError::MissingCredentials => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken => StatusCode::UNAUTHORIZED,
            AuthError::ExpiredToken => StatusCode::UNAUTHORIZED,
            AuthError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::Blocked => StatusCode::UNAUTHORIZED,
        };
        let body = Json(json!(ErrorResponse {
            session_id: "UNAUTHORIZED".into(),
            request_id: None::<String>,
            http_code: status.as_u16(),
            error_code: status.as_u16(),
            error_code_str: status.to_string(),
            message: self.to_string(),
        }));
        (status, body).into_response()
    }
}

/// Validate a raw JWT bearer token and resolve it to an authenticated
/// [`Session`].
///
/// This is the single source of truth for token validation. It is
/// shared by two callers so both apply *identical* signature, claim,
/// expiry, DID-match and ACL checks:
/// - [`Session::from_request_parts`] — the `Authorization: Bearer`
///   header path used by all REST endpoints and by native WebSocket
///   clients (which can set request headers on the upgrade).
/// - [`crate::handlers::websocket::websocket_handler`] — the
///   `Sec-WebSocket-Protocol` subprotocol path used by browsers, which
///   cannot set an `Authorization` header on `new WebSocket(...)`.
///
/// The token's origin (header vs. subprotocol) is irrelevant here: the
/// same JWT yields the same `Session`.
pub(crate) async fn authenticate_token(
    state: &SharedData,
    token: &str,
) -> Result<Session, AuthError> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_audience(&["ATM"]);
    validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id"]);

    let token_data: TokenData<SessionClaims> = match jsonwebtoken::decode::<SessionClaims>(
        token,
        &state.config.security.jwt_decoding_key,
        &validation,
    ) {
        Ok(token_data) => token_data,
        Err(err) => {
            event!(Level::WARN, "Decoding JWT failed {:?}", err);
            return Err(AuthError::InvalidToken);
        }
    };

    let session_id = token_data.claims.session_id.clone();
    let did = token_data.claims.sub.clone();
    let did_hash = digest(&did);

    // Everything has passed token wise - expensive database operations happen here
    let mut saved_session: Session = state
        .database
        .get_session(&session_id, &did)
        .await
        .map_err(|e| {
            error!(
                "{}: Couldn't get session from database! Reason: {}",
                session_id, e
            );
            AuthError::InternalServerError(format!(
                "Couldn't get session from database! Reason: {e}"
            ))
        })?
        .into();

    // Defence in depth: the session record's DID must match the
    // JWT's `sub`. If they diverge, the session was either created
    // with a different DID (storage corruption, replay across
    // tenants) or get_session returned a partially populated
    // record (legacy data, schema drift). Either way the handler
    // would silently see the wrong DID — surface as InvalidToken
    // here so the failure is loud and the client re-authenticates.
    if saved_session.did != did {
        warn!(
            session_id = %session_id,
            jwt_did = %did,
            session_did = %saved_session.did,
            "JWT sub does not match session DID — rejecting"
        );
        return Err(AuthError::InvalidToken);
    }

    // Check if ACL is satisfied
    if saved_session.acls.get_blocked() {
        info!("DID({}) is blocked from connecting", did);
        return Err(AuthError::Blocked);
    }

    // Update the expires at time
    saved_session.expires_at = token_data.claims.exp;

    debug!(session_id, did_hash, "JWT auth accepted");

    Ok(saved_session)
}

impl<S> FromRequestParts<S> for Session
where
    SharedData: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let state = parts
            .extract_with_state::<SharedData, _>(_state)
            .await
            .map_err(|e| {
                error!("Couldn't get SharedData state! Reason: {}", e);
                AuthError::InternalServerError(format!(
                    "Couldn't get SharedData state! Reason: {e}"
                ))
            })?;

        match parts
            .extensions
            .get::<axum::extract::ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0)
        {
            Some(address) => address.to_string(),
            _ => {
                warn!("No remote address in request!");
                return Err(AuthError::MissingCredentials);
            }
        };

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                warn!("No Authorization Bearer header in request!");
                AuthError::MissingCredentials
            })?;

        authenticate_token(&state, bearer.token()).await
    }
}

/// Extractor that wraps `Session` and never rejects.
///
/// When a valid `Authorization: Bearer` token is present the inner `Session`
/// is fully populated (i.e. `session.authenticated == true`). When the header
/// is absent or invalid an anonymous session is synthesised using the
/// mediator's global default ACL — this is intentional for inter-mediator
/// relay requests sent by a remote `ForwardingProcessor`.
pub struct MaybeSession(pub Session);

impl<S> FromRequestParts<S> for MaybeSession
where
    SharedData: FromRef<S>,
    S: Send + Sync + Debug,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Session::from_request_parts(parts, state).await {
            Ok(session) => Ok(MaybeSession(session)),
            Err(_) => {
                let shared = SharedData::from_ref(state);
                Ok(MaybeSession(Session {
                    session_id: "ANON-INBOUND".to_string(),
                    acls: shared.config.security.global_acl_default.clone(),
                    ..Default::default()
                }))
            }
        }
    }
}
