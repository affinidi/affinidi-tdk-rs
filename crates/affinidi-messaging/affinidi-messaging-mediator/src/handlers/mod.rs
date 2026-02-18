use crate::{SharedData, database::session::Session};
use affinidi_messaging_mediator_common::errors::AppError;
use affinidi_messaging_sdk::messages::SuccessResponse;
use axum::{
    Json, Router,
    extract::State,
    response::IntoResponse,
    routing::{delete, get, post},
};
use http::StatusCode;

pub mod authenticate;
pub mod inbox_fetch;
pub mod message_delete;
pub mod message_inbound;
pub mod message_list;
pub mod message_outbound;
pub(crate) mod oob_discovery;
pub mod websocket;
pub mod well_known_did_fetch;

pub fn application_routes(api_prefix: &str, shared_data: &SharedData) -> Router {
    let mut app = Router::new()
        // Inbound message handling from ATM clients
        .route("/inbound", post(message_inbound::message_inbound_handler))
        // Outbound message handling to ATM clients
        .route(
            "/outbound",
            post(message_outbound::message_outbound_handler),
        )
        .route("/fetch", post(inbox_fetch::inbox_fetch_handler))
        // Listing of messages for a DID
        .route(
            "/list/{did_hash}/{folder}",
            get(message_list::message_list_handler),
        )
        // Delete/remove messages stored in ATM
        .route("/delete", delete(message_delete::message_delete_handler))
        // Authentication step 1/2 - Client requests challenge from server
        .route(
            "/authenticate/challenge",
            post(authenticate::authentication_challenge),
        )
        // Authentication step 2/2 - Client sends encrypted challenge to server
        .route("/authenticate", post(authenticate::authentication_response))
        .route(
            "/authenticate/refresh",
            post(authenticate::authentication_refresh),
        )
        // Websocket endpoint for ATM clients
        .route("/ws", get(websocket::websocket_handler))
        // Out Of Band Discovery Routes
        // POST   :: /oob - Client can post a plaintext DIDComm message here to create a shortened OOB URL
        // GET    :: /oob?<id> - Unauthenticated endpoint to retrieve an OOB Invitation request
        // DELETE :: /oob?<id> - Remove the Invitation URL
        .route("/oob", post(oob_discovery::oob_invite_handler))
        .route("/oob", get(oob_discovery::oobid_handler))
        .route("/oob", delete(oob_discovery::delete_oobid_handler))
        // Helps to test if you are who you think you are
        .route("/whoami", get(whoami_handler))
        .route(
            "/.well-known/did",
            get(well_known_did_fetch::well_known_did_fetch_handler),
        );

    if shared_data.config.mediator_did_doc.is_some() {
        app = app.route(
            "/.well-known/did.json",
            get(well_known_did_fetch::well_known_did_doc_handler),
        )
        .route(
            "/.well-known/did.jsonl",
            get(well_known_did_fetch::well_known_did_doc_handler),
        );
    }

    let mut router = Router::new();
    router = if api_prefix.is_empty() || api_prefix == "/" {
        router.merge(app)
    } else {
        router.nest(api_prefix, app)
    };
    router.with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Secure Messaging Mediator Service, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}

/// Handler that returns the DID registered for this session
pub async fn whoami_handler(
    session: Session,
) -> Result<(StatusCode, Json<SuccessResponse<String>>), AppError> {
    Ok((
        StatusCode::OK,
        Json(SuccessResponse {
            sessionId: "".to_string(),
            data: Some(session.did.clone()),
            httpCode: StatusCode::OK.as_u16(),
            errorCode: 0,
            errorCodeStr: "NA".to_string(),
            message: "Success".to_string(),
        }),
    ))
}
