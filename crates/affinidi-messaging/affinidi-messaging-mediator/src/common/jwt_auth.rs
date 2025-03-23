use crate::{
    SharedData,
    database::session::{Session, SessionClaims},
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
use tracing::{Level, error, event, info, warn};

// Payload contents of the JWT
// All times are in seconds since UNIX EPOCH
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    pub aud: Vec<String>, // Intended Audience
    pub client_id: String,
    pub exp: u64,         // What does this JWT Expire
    pub iat: u64,         // Issued at this time
    pub iss: String,      // Who issued this JWT?
    pub jti: String,      // JWT ID
    pub nbf: u64,         // JWT is not valid before this time
    pub scp: Vec<String>, // ???
    pub sub: String,      // subject - who this JWT refers to
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
                write!(f, "Internal Server Error: {}", message)
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
            sessionId: "UNAUTHORIZED".into(),
            httpCode: status.as_u16(),
            errorCode: status.as_u16(),
            errorCodeStr: status.to_string(),
            message: self.to_string(),
        }));
        (status, body).into_response()
    }
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
                    "Couldn't get SharedData state! Reason: {}",
                    e
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

        let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.set_audience(&["ATM"]);
        validation.set_required_spec_claims(&["exp", "sub", "aud", "session_id"]);

        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| {
                warn!("No Authorization Bearer header in request!");
                AuthError::MissingCredentials
            })?;

        let token_data: TokenData<SessionClaims> = match jsonwebtoken::decode::<SessionClaims>(
            bearer.token(),
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
        let mut saved_session = state
            .database
            .get_session(&session_id, &did)
            .await
            .map_err(|e| {
                error!(
                    "{}: Couldn't get session from database! Reason: {}",
                    session_id, e
                );
                AuthError::InternalServerError(format!(
                    "Couldn't get session from database! Reason: {}",
                    e
                ))
            })?;

        // Check if ACL is satisfied
        if saved_session.acls.get_blocked() {
            info!("DID({}) is blocked from connecting", did);
            return Err(AuthError::Blocked);
        }

        // Update the expires at time
        saved_session.expires_at = token_data.claims.exp;

        info!(
            "{}: Protected connection accepted from did_hash({})",
            &session_id, &did_hash
        );

        Ok(saved_session)
    }
}
