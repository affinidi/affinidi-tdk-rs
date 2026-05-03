use super::helpers::create_random_string;
use super::{AuthenticationChallenge, ChallengeBody};
use crate::{
    SharedData,
    common::acl_checks::ACLCheck,
    database::session::{Session, SessionState},
};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::{
    messages::problem_report::{ProblemReportScope, ProblemReportSorter},
    protocols::mediator::{accounts::AccountType, acls::MediatorACLSet},
};
use axum::{Json, extract::State};
use http::StatusCode;
use sha256::digest;
use tracing::{Instrument, Level, debug, info, span};

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
        refresh_token_hash: None,
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
            return Err(MediatorError::problem(
                25,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authentication.blocked",
                "DID is blocked",
                vec![],
                StatusCode::FORBIDDEN,
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

        state
            .database
            .create_session(&session.to_store_session())
            .await?;

        metrics::counter!(crate::common::metrics::names::AUTH_CHALLENGES_TOTAL).increment(1);
        debug!("Challenge sent to {}", session.did);

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id.clone(),
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
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
