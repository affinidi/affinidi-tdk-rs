use crate::{
    SharedData,
    common::authz::{self, Capability},
    common::session::Session,
};
use affinidi_messaging_mediator_common::{
    errors::{AppError, MediatorError, SuccessResponse},
    store::DeletionAuthority,
};
use affinidi_messaging_sdk::messages::compat::UnpackMetadata;
use affinidi_messaging_sdk::messages::{
    DeleteMessageRequest, DeleteMessageResponse, GenericDataStruct,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, debug, span};

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
        if authz::require_capability(&session.acls, Capability::Local).is_err() {
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

        debug!("Deleting ({}) messages", body.message_ids.len());
        if body.message_ids.len() > state.limits().deleted_messages {
            return Err(MediatorError::problem_with_log(
                43,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "api.message_delete.limit",
                "Invalid limit ({1}). Maximum of 100 messages can be deleted per transaction",
                vec![body.message_ids.len().to_string()],
                StatusCode::BAD_REQUEST,
                "Invalid limit",
            )
            .into());
        }
        let mut deleted: DeleteMessageResponse = DeleteMessageResponse::default();

        for message in &body.message_ids {
            // Only while someone is watching: read who the message was between,
            // so its `deleted` event names both parties.
            let parties = if state.monitor.is_active() {
                state
                    .database
                    .get_message(&session.did_hash, message)
                    .await
                    .ok()
                    .flatten()
                    .map(|m| (m.from_address, m.to_address, m.msg))
            } else {
                None
            };
            let result: Result<(), MediatorError> = state
                .database
                .delete_message(
                    message,
                    DeletionAuthority::Owner {
                        did_hash: session.did_hash.clone(),
                    },
                )
                .await;

            match result {
                Ok(_) => {
                    let (from, to, body) = parties.unwrap_or_default();
                    state.monitor.deleted(
                        message,
                        &session.did_hash,
                        from.as_deref(),
                        to.as_deref(),
                        crate::monitor::Channel::Rest,
                        body.as_deref(),
                    );
                    deleted.success.push(message.into())
                }
                Err(err) => {
                    debug!(message_id = message, error = %err, "Delete failed (may already be deleted)");
                    deleted.errors.push((message.into(), err.to_string()));
                }
            }
        }

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(deleted),
            }),
        ))
    }
    .instrument(_span)
    .await
}
