use crate::{SharedData, database::session::Session};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    GetMessagesResponse,
    fetch::FetchOptions,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
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
            return Err(MediatorError::MediatorError(
                40,
                session.session_id,
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "authorization.local".into(),
                    "DID isn't local to the mediator".into(),
                    vec![],
                    None,
                )),
                StatusCode::FORBIDDEN.as_u16(),
                "DID isn't local to the mediator".to_string(),
            )
            .into());
        }

        // Check options
        if body.limit< 1 || body.limit > 100 {
            return Err(MediatorError::MediatorError(
                41,
                session.session_id,
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "api.inbox_fetch.limit".into(),
                    "Invalid limit ({1}). Must be 1-100 in range".into(),
                    vec![body.limit.to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Invalid limit".to_string(),
            )
            .into());
        }

        // Check for valid start_id (unixtime in milliseconds including+1 digit so we are ok for another 3,114 years!)
        // Supports up to 999 messages per millisecond
        let re = Regex::new(r"\d{13,14}-\d{1,3}$").unwrap();
        if let Some(start_id) = &body.start_id && ! re.is_match(start_id) {
                return Err(MediatorError::MediatorError(
                    42,
                    session.session_id,
                    None,
                    Box::new(ProblemReport::new(
                        ProblemReportSorter::Error,
                        ProblemReportScope::Protocol,
                        "api.inbox_fetch.start_id".into(),
                        "start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {1}".into(),
                        vec![start_id.to_string()],
                        None,
                    )),
                    StatusCode::BAD_REQUEST.as_u16(),
                    format!("start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {}", start_id),
                )
                .into());
            }

        // Fetch messages if possible
        let results = state.database.fetch_messages(&session.session_id, &session.did_hash, &body).await.map_err(|e| {MediatorError::MediatorError(
            14,
            session.session_id.clone(),
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
            format!("Database transaction error: {}", e),
        )})?;

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
