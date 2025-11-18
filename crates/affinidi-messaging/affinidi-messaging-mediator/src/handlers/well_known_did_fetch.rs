use affinidi_did_common::{Document, service::Service};
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{Json, extract::State};
use http::StatusCode;
use tracing::{Instrument, Level, span};
use tracing_subscriber::fmt::format::json;

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
pub async fn well_known_web_did_handler(
    State(state): State<SharedData>,
) -> Result<Json<serde_json::Value>, AppError> {
    let _span = span!(Level::DEBUG, "well_known_web_did_handler");
    async move {
        let doc = match state.config.mediator_did_doc {
            Some(doc) => doc,
            _ => {
                return Err(MediatorError::ConfigError(
                    48,
                    "NA".to_string(),
                    "No Mediator DID Document is configured".to_string(),
                )
                .into());
            }
        };

        let mut doc_obj = serde_json::to_value(&doc).map_err(|e| {
            MediatorError::ConfigError(49, "NA".to_string(), format!("serialize error: {}", e))
        })?;

        // If there is a "service" array, replace each entry with the web DID shape:
        // { "id": ..., "type": <first element of type_ or fallback>, "serviceEndpoint": ... }
        if let Some(service_arr) = doc_obj.get_mut("service").and_then(|v| v.as_array_mut()) {
            let new_services: Vec<serde_json::Value> = service_arr
                .iter()
                .map(|s| {
                    // id
                    let id = s.get("id").cloned().unwrap_or(serde_json::Value::Null);
                    // type_ -> take first element if it's an array, otherwise use as-is.
                    let t = s
                        .get("type")
                        .and_then(|tval| {
                            if tval.is_array() {
                                tval.as_array().and_then(|arr| arr.first().cloned())
                            } else {
                                Some(tval.clone())
                            }
                        })
                        .unwrap_or(serde_json::Value::Null);

                    // service_endpoint -> serviceEndpoint (web DID uses camelCase)
                    let endpoint = s
                        .get("serviceEndpoint")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    serde_json::json!({
                        "id": id,
                        "type": t,
                        "serviceEndpoint": endpoint
                    })
                })
                .collect();

            // Replace the original service array with the transformed array.
            *service_arr = new_services;
        }

        // Return the transformed JSON value directly so we produce the web DID shape.
        Ok(Json(doc_obj))
    }
    .instrument(_span)
    .await
}
