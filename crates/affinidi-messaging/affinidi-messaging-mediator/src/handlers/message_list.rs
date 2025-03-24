use crate::{SharedData, database::session::Session};
use affinidi_messaging_didcomm::UnpackMetadata;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{Folder, GenericDataStruct, MessageList};
use axum::{
    Json,
    extract::{Path, State},
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
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
            return Err(MediatorError::ACLDenied("DID does not have LOCAL access".into()).into());
        }

        // Check that the DID hash matches the session DID
        // TODO: In the future, add support for lists of DID's owned by the session owner
        if session.did_hash != did_hash {
            return Err(MediatorError::PermissionError(
                session.session_id,
                "You don't have permission to access this resource.".into(),
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
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(messages),
            }),
        ))
    }
    .instrument(_span)
    .await
}
