use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    GetMessagesResponse,
    fetch::FetchOptions,
    problem_report::{ProblemReportScope, ProblemReportSorter},
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
            return Err(MediatorError::problem(
                40, session.session_id, None,
                ProblemReportSorter::Error, ProblemReportScope::Protocol,
                "authorization.local",
                "DID isn't local to the mediator",
                vec![], StatusCode::FORBIDDEN,
            )
            .into());
        }

        // Check options
        if body.limit< 1 || body.limit > 100 {
            return Err(MediatorError::problem_with_log(
                41, session.session_id, None,
                ProblemReportSorter::Error, ProblemReportScope::Protocol,
                "api.inbox_fetch.limit",
                "Invalid limit ({1}). Must be 1-100 in range",
                vec![body.limit.to_string()], StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }

        // Check for valid start_id (unixtime in milliseconds including+1 digit so we are ok for another 3,114 years!)
        // Supports up to 999 messages per millisecond
        static RE: std::sync::LazyLock<Regex> = std::sync::LazyLock::new(|| {
            Regex::new(r"\d{13,14}-\d{1,3}$").expect("hardcoded regex is valid")
        });
        let re = &*RE;
        if let Some(start_id) = &body.start_id && ! re.is_match(start_id) {
                return Err(MediatorError::problem_with_log(
                    42, session.session_id, None,
                    ProblemReportSorter::Error, ProblemReportScope::Protocol,
                    "api.inbox_fetch.start_id",
                    "start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {1}",
                    vec![start_id.to_string()], StatusCode::BAD_REQUEST,
                    format!("start_id isn't valid. Should match UNIX_EPOCH in milliseconds + `-(0..999)`. Received: {start_id}"),
                )
                .into());
            }

        // Fetch messages if possible
        let results = state.database.fetch_messages(&session.session_id, &session.did_hash, &body).await.map_err(|e| {MediatorError::problem_with_log(
            14, session.session_id.clone(), None,
            ProblemReportSorter::Error, ProblemReportScope::Protocol,
            "me.res.storage.error",
            "Database transaction error: {1}",
            vec![e.to_string()], StatusCode::SERVICE_UNAVAILABLE,
            format!("Database transaction error: {e}"),
        )})?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(results),
            }),
        ))
    }
    .instrument(_span)
    .await
}
