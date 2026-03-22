use crate::{SharedData, database::session::Session};
use affinidi_messaging_didcomm::UnpackMetadata;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    DeleteMessageRequest, DeleteMessageResponse, GenericDataStruct,
    problem_report::{ProblemReport, ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, debug, info, span};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct ResponseData {
    pub body: String,
    pub metadata: UnpackMetadata,
}
impl GenericDataStruct for ResponseData {}

/// Deletes a specific message from ATM
/// Returns a list of messages that were deleted
/// ACL_MODE: Requires LOCAL access
pub async fn message_delete_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<DeleteMessageRequest>,
) -> Result<(StatusCode, Json<SuccessResponse<DeleteMessageResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_delete_handler",
        session = session.session_id,
        did = session.did,
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

        debug!("Deleting ({}) messages", body.message_ids.len());
        if body.message_ids.len() > state.config.limits.deleted_messages {
            return Err(MediatorError::MediatorError(
                43,
                session.session_id,
                None,
                Box::new(ProblemReport::new(
                    ProblemReportSorter::Error,
                    ProblemReportScope::Protocol,
                    "api.message_delete.limit".into(),
                    "Invalid limit ({1}). Maximum of 100 messages can be deleted per transaction"
                        .into(),
                    vec![body.message_ids.len().to_string()],
                    None,
                )),
                StatusCode::BAD_REQUEST.as_u16(),
                "Invalid limit".to_string(),
            )
            .into());
        }
        let mut deleted: DeleteMessageResponse = DeleteMessageResponse::default();

        for message in &body.message_ids {
            debug!("Deleting message: message_id({})", message);
            let result = state
                .database
                .0
                .delete_message(Some(&session.session_id), &session.did_hash, message, None)
                .await;

            match result {
                Ok(_) => deleted.success.push(message.into()),
                Err(err) => {
                    // This often occurs because the message was already deleted, and client is trying to delete it again
                    info!(
                        "{}: failed to delete msg({}). Reason: {}",
                        session.session_id, message, err
                    );
                    deleted.errors.push((message.into(), err.to_string()));
                }
            }
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(deleted),
            }),
        ))
    }
    .instrument(_span)
    .await
}
