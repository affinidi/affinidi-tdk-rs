use crate::{SharedData, common::session::Session};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    Folder, GenericDataStruct, MessageList,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{Instrument, Level, debug, span};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

/// Retrieves lists of messages either from the send or receive queue
/// ACL_MODE: Rquires LOCAL access
/// # Parameters
/// - `session`: Session information
/// - `folder`: Folder to retrieve messages from
/// - `did_hash`: sha256 hash of the DID we are checking
pub async fn message_list_handler(
    session: Session,
    Path((did_hash, folder)): Path<(String, Folder)>,
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<MessageList>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_list_handler",
        session = session.session_id,
        session_did = session.did,
        did_hash = did_hash,
        folder = folder.to_string()
    );
    async move {
        // ACL Check
        if !session.acls.get_local() {
            return Err(MediatorError::problem(
                40,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.local",
                "DID isn't local to the mediator",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        // Sessions are scoped to a single authenticated DID — listing
        // is allowed only for that DID. Multi-DID listing (one session
        // owner aggregating across several DIDs) would need a session-
        // owner concept above the DID and an owner→DIDs index in the
        // store; tracked in PR #286's follow-up section.
        if session
            .did_hash
            .as_bytes()
            .ct_eq(did_hash.as_bytes())
            .unwrap_u8()
            == 0
        {
            return Err(MediatorError::problem(
                45,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.permission",
                "DID hash does not match authenticated session",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        let messages = state
            .database
            .list_messages(
                &did_hash,
                folder,
                None,
                state.config.limits.listed_messages as u32,
            )
            .await?;

        debug!("List contains ({}) messages", messages.len());
        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(messages),
            }),
        ))
    }
    .instrument(_span)
    .await
}
