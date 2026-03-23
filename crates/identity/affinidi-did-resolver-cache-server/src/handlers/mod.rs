use crate::{SharedData, config::Config};
use axum::{Json, Router, extract::State, response::IntoResponse, routing::get};
use tracing::info;

pub(crate) mod http;
pub(crate) mod websocket;

pub fn application_routes(shared_data: &SharedData, config: &Config) -> Router {
    let mut app = Router::new();

    if config.enable_websocket_endpoint {
        info!("Enabling WebSocket Resolver endpoint");
        app = app.route("/ws", get(websocket::websocket_handler));
    }

    if config.enable_http_endpoint {
        info!("Enabling HTTP Resolver endpoint");
        app = app.route("/resolve/{did}", get(http::resolver_handler));
    }

    Router::new()
        .nest("/did/v1", app)
        .with_state(shared_data.to_owned())
}

pub async fn health_checker_handler(State(state): State<SharedData>) -> impl IntoResponse {
    let message: String = format!(
        "Affinidi Trust Network - DID Cache, Version: {}, Started: UTC {}",
        env!("CARGO_PKG_VERSION"),
        state.service_start_timestamp.format("%Y-%m-%d %H:%M:%S"),
    );

    let response_json = serde_json::json!({
        "status": "success".to_string(),
        "message": message,
    });
    Json(response_json)
}
