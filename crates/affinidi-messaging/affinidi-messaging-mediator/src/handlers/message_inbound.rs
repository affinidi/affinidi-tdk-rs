use crate::{SharedData, database::session::Session, messages::inbound::handle_inbound};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::sending::InboundMessageResponse;
use axum::{Json, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, span};

#[derive(Serialize, Deserialize, Debug)]
pub struct RecipientHeader {
    pub kid: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Recipient {
    pub header: RecipientHeader,
    pub encrypted_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct InboundMessage {
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub iv: String,
    pub ciphertext: String,
    pub tag: String,
}

/// Handles inbound messages to the mediator
/// ACL_MODE: Rquires LOCAL access
///
pub async fn message_inbound_handler(
    session: Session,
    State(state): State<SharedData>,
    Json(body): Json<InboundMessage>,
) -> Result<(StatusCode, Json<SuccessResponse<InboundMessageResponse>>), AppError> {
    let _span = span!(
        Level::DEBUG,
        "message_inbound_handler",
        session = session.session_id
    );
    async move {
        // ACL Check
        if !session.acls.get_send_messages().0 {
            return Err(
                MediatorError::ACLDenied("DID does not have send/inbound access".into()).into(),
            );
        }

        let s = match serde_json::to_string(&body) {
            Ok(s) => s,
            Err(e) => {
                return Err(MediatorError::ParseError(
                    session.session_id.clone(),
                    "InboundMessage".into(),
                    e.to_string(),
                )
                .into());
            }
        };

        let response = handle_inbound(&state, &session, &s).await?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: session.session_id,
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(response),
            }),
        ))
    }
    .instrument(_span)
    .await
}
