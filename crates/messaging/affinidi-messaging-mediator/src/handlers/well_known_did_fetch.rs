use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{Json, extract::State, response::IntoResponse};
use http::{HeaderValue, StatusCode, header};
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

/// Serve the canonical mediator DID Document at `/.well-known/did.json`
/// for did:web-style resolution. The body is the DID Document only —
/// for did:webvh sources the loader extracts `state` from the original
/// log entry so this handler returns the same shape for either source.
pub async fn well_known_did_json_handler(
    State(state): State<SharedData>,
) -> Result<impl IntoResponse, AppError> {
    let _span = span!(Level::DEBUG, "well_known_did_json_handler");
    async move {
        let doc = state
            .config
            .mediator_did_doc
            .as_ref()
            .filter(|doc| !doc.is_empty())
            .cloned()
            .ok_or_else(|| -> AppError {
                MediatorError::ConfigError(
                    48,
                    "NA".to_string(),
                    "No Mediator DID Document is configured".to_string(),
                )
                .into()
            })?;

        Ok((
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/did+json"),
            )],
            doc,
        ))
    }
    .instrument(_span)
    .await
}

/// Serve the raw webvh log entry stream at `/.well-known/did.jsonl` so
/// did:webvh resolvers can verify the DID's history. The body is the
/// JSON-Lines log loaded from `did_web_self_hosted` verbatim. Only
/// registered when the loader saw a `LogEntry` shape on disk; did:web
/// sources omit this route (the resolver shouldn't be asking).
pub async fn well_known_did_jsonl_handler(
    State(state): State<SharedData>,
) -> Result<impl IntoResponse, AppError> {
    let _span = span!(Level::DEBUG, "well_known_did_jsonl_handler");
    async move {
        let log = state
            .config
            .mediator_did_log
            .as_ref()
            .filter(|s| !s.is_empty())
            .cloned()
            .ok_or_else(|| -> AppError {
                MediatorError::ConfigError(
                    48,
                    "NA".to_string(),
                    "No Mediator did:webvh log entry is configured".to_string(),
                )
                .into()
            })?;

        Ok((
            StatusCode::OK,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/jsonl"),
            )],
            log,
        ))
    }
    .instrument(_span)
    .await
}
