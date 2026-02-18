use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{Json, extract::State};
use http::StatusCode;
use tracing::{Instrument, Level, span};

use crate::SharedData;

/// Returns the DID for the mediator
pub async fn well_known_did_fetch_handler(
    State(state): State<SharedData>,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    let _span = span!(Level::DEBUG, "well_known_did_fetch_handler");
    async move {
        let did = state.config.clone().mediator_did;

        Ok((
            StatusCode::OK,
            Json(SuccessResponse {
                sessionId: "".to_string(),
                data: Some(did),
                httpCode: StatusCode::OK.as_u16(),
                errorCode: 0,
                errorCodeStr: "NA".to_string(),
                message: "Success".to_string(),
            }),
        ))
    }
    .instrument(_span)
    .await
}

/// Handles resolution of the well-known DID for the mediator when self hosting a did:web DID
pub async fn well_known_did_doc_handler(
    State(state): State<SharedData>,
) -> Result<String, AppError> {
    let _span = span!(Level::DEBUG, "well_known_did_doc_handler");
    async move {
        state.config.mediator_did_doc
            .as_ref()
            .filter(|doc| !doc.is_empty())
            .map(|doc| doc.clone())
            .ok_or_else(|| {
                MediatorError::ConfigError(
                    48,
                    "NA".to_string(),
                    "No Mediator DID Document is configured".to_string(),
                ).into()
            })
    }
    .instrument(_span)
    .await
}
