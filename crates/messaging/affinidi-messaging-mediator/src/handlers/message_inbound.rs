use crate::{SharedData, common::session::Session, messages::inbound::handle_inbound};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError, SuccessResponse};
use affinidi_messaging_sdk::messages::{
    problem_report::{ProblemReportScope, ProblemReportSorter},
    sending::InboundMessageResponse,
};
use axum::{Json, extract::State};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::{Instrument, Level, span};

use crate::common::metrics::names;

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
/// ACL_MODE: Requires LOCAL access
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
            metrics::counter!(names::ACL_DENIALS_TOTAL, "action" => "send").increment(1);
            return Err(MediatorError::problem(
                44,
                session.session_id,
                None,
                ProblemReportSorter::Error,
                ProblemReportScope::Protocol,
                "authorization.send",
                "DID isn't allowed to send messages through this mediator",
                vec![],
                StatusCode::FORBIDDEN,
            )
            .into());
        }

        let s = match serde_json::to_string(&body) {
            Ok(s) => s,
            Err(e) => {
                return Err(MediatorError::problem_with_log(
                    19,
                    session.session_id,
                    None,
                    ProblemReportSorter::Warning,
                    ProblemReportScope::Message,
                    "message.serialize",
                    "Couldn't serialize DIDComm message envelope. Reason: {1}",
                    vec![e.to_string()],
                    StatusCode::BAD_REQUEST,
                    "Couldn't serialize DIDComm message envelope",
                )
                .into());
            }
        };

        metrics::counter!(names::MESSAGES_INBOUND_TOTAL).increment(1);
        metrics::counter!(names::MESSAGE_BYTES_INBOUND_TOTAL).increment(s.len() as u64);

        let response = handle_inbound(&state, &session, &s).await?;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                session_id: session.session_id,
                http_code: StatusCode::OK.as_u16(),
                error_code: 0,
                error_code_str: "NA".to_string(),
                message: "Success".to_string(),
                data: Some(response),
            }),
        ))
    }
    .instrument(_span)
    .await
}
