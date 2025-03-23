use crate::{SharedData, database::session::Session};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{GetMessagesResponse, fetch::FetchOptions};
use axum::{Json, extract::State};
use http::StatusCode;
use regex::Regex;
use tracing::{Instrument, Level, span};

/// Fetches available messages from the inbox
/// ACL_MODE: Rquires LOCAL access
///
/// # Parameters
/// - `session`: Session information
/// - `folder`: Folder to retrieve messages from
/// - `did_hash`: sha256 hash of the DID we are checking
pub async fn inbox_fetch_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<FetchOptions>,
) -> Result<(StatusCode, Json<SuccessResponse<GetMessagesResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "inbox_fetch_handler",
        session = session.session_id,
        session_did = session.did,
        fetch.limit = body.limit,
        fetch.start_id = body.start_id,
        fetch.delete_policy = body.delete_policy.to_string()
    );
    async move {
        // ACL Check
        if !session.acls.get_local() {
            return Err(MediatorError::ACLDenied("DID does not have LOCAL access".into()).into());
        }

        // Check options
        if body.limit< 1 || body.limit > 100 {
            return Err(MediatorError::ConfigError(session.session_id, format!("limit must be between 1 and 100 inclusive. Received limit({})", body.limit)).into());
        }

        // Check for valid start_id (unixtime in milliseconds including+1 digit so we are ok for another 3,114 years!)
        // Supports up to 999 messages per millisecond
        let re = Regex::new(r"\d{13,14}-\d{1,3}$").unwrap();
        if let Some(start_id) = &body.start_id {
            if ! re.is_match(start_id) {
                return Err(MediatorError::ConfigError(session.session_id, format!("start_id isn't valid. Should match UNIX_EPOCH in milliseconds + -(0..999). Received start_id({})", start_id)).into());
            }
        }

        // Fetch messages if possible
        let results = state.database.fetch_messages(&session.session_id, &session.did_hash, &body).await?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(results),
            }),
        ))
    }
    .instrument(_span)
    .await
}
