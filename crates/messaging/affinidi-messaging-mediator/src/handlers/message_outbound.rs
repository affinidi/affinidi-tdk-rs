use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    GetMessagesRequest, GetMessagesResponse,
    problem_report::{ProblemReportScope, ProblemReportSorter},
};
use axum::{Json, extract::State};
use http::StatusCode;
use tracing::{Instrument, Level, debug, span};

use crate::{SharedData, database::session::Session};

/// Delivers messages to the client for given message_ids
/// outbound refers to outbound from the mediator perspective
/// ACL_MODE: Rquires LOCAL access
pub async fn message_outbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<GetMessagesRequest>,
) -> Result<(StatusCode, Json<SuccessResponse<GetMessagesResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_outbound_handler",
        session = session.session_id,
        delete = body.delete,
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

        debug!(
            "Client has asked to get ({}) messages",
            body.message_ids.len()
        );

        let mut messages = GetMessagesResponse::default();

        for msg_id in &body.message_ids {
            debug!("getting message with id: {}", msg_id);
            match state.database.get_message(&session.did_hash, msg_id).await {
                Ok(Some(msg)) => {
                    debug!("Got message: {:?}", msg);
                    messages.success.push(msg);

                    if body.delete {
                        debug!("Deleting message: {}", msg_id);
                        match state
                            .database
                            .handler
                            .delete_message(
                                Some(&session.session_id),
                                &session.did_hash,
                                msg_id,
                                None,
                            )
                            .await
                        {
                            Ok(_) => {
                                debug!("Deleted message: {}", msg_id);
                            }
                            Err(err) => {
                                debug!("Error deleting message: {:?}", err);
                                messages
                                    .delete_errors
                                    .push((msg_id.clone(), err.to_string()));
                            }
                        }
                    }
                }
                Ok(None) => {
                    debug!("Message not found: {}", msg_id);
                    messages
                        .get_errors
                        .push((msg_id.clone(), "Message not found".to_string()));
                }
                Err(err) => {
                    debug!("Error getting message: {:?}", err);
                    messages.get_errors.push((msg_id.clone(), err.to_string()));
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
                data: Some(messages),
            }),
        ))
    }
    .instrument(_span)
    .await
}
