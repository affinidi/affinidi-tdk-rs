//! TSP client authentication — mint the same JWT session as DIDComm.
//!
//! A TSP client (whose VID is a DID, per the phase-1 DID-VID constraint) reuses
//! the protocol-agnostic `POST /authenticate/challenge` to obtain a challenge,
//! signs that challenge with its VID's Ed25519 key, and POSTs the signature
//! here. The mediator resolves the VID's signing key from its DID document and
//! verifies the signature — no mediator TSP keys and no decryption are needed.
//! On success it mints the **identical** EdDSA `SessionClaims` access+refresh
//! JWT pair the DIDComm path issues, so every downstream ACL / pickup / WS gate
//! is reused unchanged (the session is DID-keyed and protocol-agnostic).

use super::helpers::{_create_access_token, _create_refresh_token, create_random_string};
use crate::{
    SharedData,
    common::session::{Session, SessionState},
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    AuthorizationResponse,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use affinidi_tsp::DidVidResolver;
use affinidi_tsp::crypto::signing;
use axum::{Json, extract::State};
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, debug, span};

/// Request body for `POST /tsp/authenticate`.
#[derive(Serialize, Deserialize, Debug)]
pub struct TspAuthenticateBody {
    /// The client's VID — a DID, per the phase-1 DID-VID constraint.
    pub vid: String,
    /// The `session_id` returned by `POST /authenticate/challenge`.
    pub session_id: String,
    /// base64url(no-pad) of the Ed25519 signature over the issued `challenge`.
    pub signature: String,
}

/// Authentication step 2/2 for a TSP client: verify the signed challenge and
/// mint the access + refresh JWT pair.
pub async fn tsp_authentication_response(
    State(state): State<SharedData>,
    Json(body): Json<TspAuthenticateBody>,
) -> Result<(StatusCode, Json<SuccessResponse<AuthorizationResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "tsp_authentication_response",
        session_id = body.session_id
    );
    async move {
        // VID must be a DID (phase-1 DID-VID constraint).
        if !body.vid.starts_with("did:") {
            return Err(MediatorError::problem(
                29,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.invalid_vid",
                "TSP authentication requires a `did:`-based VID",
                vec![],
                StatusCode::BAD_REQUEST,
            )
            .into());
        }

        // Load the challenge session and check it is awaiting a response.
        let mut session: Session = state
            .database
            .get_session(&body.session_id, &body.vid)
            .await?
            .into();
        if session.state != SessionState::ChallengeSent {
            return Err(MediatorError::problem(
                34,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.state",
                "Session is not awaiting a challenge response",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
            .into());
        }
        if session.did != body.vid {
            return Err(MediatorError::problem(
                33,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.session.mismatch",
                "VID does not match the challenge session",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
            .into());
        }

        // Decode the Ed25519 signature.
        let sig_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(body.signature.as_bytes())
            .map_err(|e| {
                MediatorError::problem(
                    28,
                    &body.session_id,
                    None,
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authentication.tsp.signature.encoding",
                    "Signature is not valid base64url: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                )
            })?;
        let signature: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
            MediatorError::problem(
                28,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.signature.length",
                "Ed25519 signature must be 64 bytes",
                vec![],
                StatusCode::BAD_REQUEST,
            )
        })?;

        // Resolve the VID → its Ed25519 signing key from the DID document.
        let resolver = DidVidResolver::new(state.did_resolver.clone());
        let resolved = resolver.resolve_did(&body.vid).await.map_err(|e| {
            MediatorError::problem(
                28,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.resolve",
                "Couldn't resolve the VID's keys: {1}",
                vec![e.to_string()],
                StatusCode::BAD_REQUEST,
            )
        })?;

        // Verify the signature over the server-issued challenge: this proves the
        // client controls the VID's signing key.
        signing::verify(
            session.challenge.as_bytes(),
            &signature,
            &resolved.signing_key,
        )
        .map_err(|_| {
            MediatorError::problem(
                32,
                &body.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.tsp.signature.invalid",
                "TSP challenge signature verification failed",
                vec![],
                StatusCode::UNAUTHORIZED,
            )
        })?;

        // Mint the same JWT pair the DIDComm path issues, rotating the session id.
        let now = state.clock.unix_secs();
        let old_sid = session.session_id.clone();
        session.session_id = create_random_string(12);
        let (access_token, access_expires_at) = _create_access_token(
            &session.did,
            &session.session_id,
            state.config.security.jwt_access_expiry,
            now,
            &state.config.security.jwt_encoding_key,
        )?;
        let refresh_expiry =
            state.config.security.jwt_refresh_expiry - state.config.security.jwt_access_expiry;
        let (refresh_token, refresh_expires_at, refresh_token_hash) = _create_refresh_token(
            &session.did,
            &session.session_id,
            refresh_expiry,
            now,
            &state.config.security.jwt_encoding_key,
        )?;

        state
            .database
            .update_session_authenticated(
                &old_sid,
                &session.session_id,
                &session.did,
                &refresh_token_hash,
            )
            .await?;

        debug!("TSP client authenticated: {}", session.did);
        metrics::counter!(crate::common::metrics::names::AUTH_SUCCESS_TOTAL).increment(1);

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(AuthorizationResponse {
                    access_token,
                    access_expires_at,
                    refresh_token,
                    refresh_expires_at,
                }),
            }),
        ))
    }
    .instrument(_span)
    .await
}

#[cfg(test)]
mod tests {
    use affinidi_did_resolver_cache_sdk::DIDCacheClient;
    use affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder;
    use affinidi_encoding::{ED25519_PUB, encode_multikey};
    use affinidi_tsp::crypto::signing;
    use affinidi_tsp::{DidVidResolver, PrivateVid};

    /// The security-critical core of TSP auth: a client signs the challenge with
    /// its VID's Ed25519 key, and the mediator — having resolved that VID's
    /// signing key from its DID document — verifies the signature. Uses a
    /// `did:key` (resolved locally, no network).
    #[tokio::test]
    async fn resolve_then_verify_challenge_signature() {
        // The client's VID and keys.
        let vid_keys = PrivateVid::generate("placeholder");
        let did = format!("did:key:{}", encode_multikey(ED25519_PUB, &vid_keys.verifying_key));

        // The client signs the server-issued challenge.
        let challenge = "a-random-32-char-challenge-string";
        let signature = signing::sign(challenge.as_bytes(), &vid_keys.signing_key).unwrap();

        // The mediator resolves the VID's signing key and verifies.
        let client = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let resolved = DidVidResolver::new(client).resolve_did(&did).await.unwrap();

        assert!(
            signing::verify(challenge.as_bytes(), &signature, &resolved.signing_key).is_ok(),
            "valid challenge signature verifies against the resolved VID key"
        );
        // A signature over a different challenge must fail.
        let other = signing::sign(b"not-the-challenge", &vid_keys.signing_key).unwrap();
        assert!(
            signing::verify(challenge.as_bytes(), &other, &resolved.signing_key).is_err(),
            "a signature over a different challenge is rejected"
        );
    }
}
