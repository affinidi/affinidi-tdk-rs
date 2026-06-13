use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, DIDMethod, ResolveResponse,
    networking::{WSRequest, WSResponse, WSResponseError, WSResponseType},
};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
};
use tokio::select;
use tracing::{Instrument, debug, info, span, warn};

use crate::{
    SharedData,
    handlers::{fetch_webvh_log, resolve_with_timeout},
};

/// Build a WSResponse, fetching the raw DID log for WebVH DIDs.
async fn build_response(response: ResolveResponse) -> WSResponseType {
    let (did_log, did_witness_log) = if response.method == DIDMethod::WEBVH {
        fetch_webvh_log(&response.did).await
    } else {
        (None, None)
    };

    WSResponseType::Response(Box::new(WSResponse {
        did: response.did.clone(),
        hash: response.did_hash,
        document: response.doc,
        did_log,
        did_witness_log,
    }))
}

/// Serialize and send a WS response. Returns `false` if the connection should
/// be closed (serialization failure or send error). Never panics — a
/// serialization failure that previously `unwrap()`ed and killed the task now
/// logs and closes the connection gracefully.
async fn send_response(socket: &mut WebSocket, message: &WSResponseType) -> bool {
    let text = match serde_json::to_string(message) {
        Ok(text) => text,
        Err(e) => {
            warn!("ws: failed to serialize response, closing connection: {e:?}");
            return false;
        }
    };
    match socket.send(Message::Text(text.into())).await {
        Ok(()) => {
            debug!("Sent response: {message:?}");
            true
        }
        Err(e) => {
            warn!("ws: Error sending response: {e:?}");
            false
        }
    }
}

/// Resolve `did` (bounded by the configured timeout) and send the response, or
/// an error response if resolution fails or times out. Returns `false` if the
/// connection should be closed.
async fn resolve_and_respond(socket: &mut WebSocket, state: &SharedData, did: String) -> bool {
    match resolve_with_timeout(&state.resolver, state.resolve_timeout, &did).await {
        Ok(response) => {
            {
                let mut stats = state.stats().await;
                stats.increment_resolver_success();
                if response.cache_hit {
                    stats.increment_cache_hit();
                }
                stats.increment_did_method_success(response.method.clone());
            }
            debug!(
                "resolved DID: ({}) cache_hit?({})",
                response.did, response.cache_hit
            );
            let message = build_response(response).await;
            send_response(socket, &message).await
        }
        Err(e) => {
            // Couldn't resolve the DID (or timed out), send an error back.
            let hash = DIDCacheClient::hash_did(&did);
            warn!("Couldn't resolve DID: ({did}) Reason: {e}");
            state.stats().await.increment_resolver_error();
            let message = WSResponseType::Error(WSResponseError {
                did,
                hash,
                error: e.to_string(),
            });
            send_response(socket, &message).await
        }
    }
}

// Handles the switching of the protocol to a websocket connection
pub async fn websocket_handler(
    //session: Session,
    ws: WebSocketUpgrade,
    State(state): State<SharedData>,
) -> impl IntoResponse {
    let _span = span!(
        tracing::Level::DEBUG,
        "websocket_handler",
        // session = session.session_id
    );
    /*async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
    .instrument(_span)
    .await*/

    async move { ws.on_upgrade(move |socket| handle_socket(socket, state)) }
        .instrument(_span)
        .await
}

/// WebSocket state machine. This is spawned per connection.
//async fn handle_socket(mut socket: WebSocket, state: SharedData, session: Session) {
async fn handle_socket(mut socket: WebSocket, state: SharedData) {
    let _span = span!(
        tracing::Level::DEBUG,
        "handle_socket",
        //session = session.session_id
    );
    async move {
        state.stats().await.increment_ws_opened();
        info!("Websocket connection established");

        loop {
            select! {
                value = socket.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            Ok(msg) => {
                                match msg {
                                    Message::Text(msg) => {
                                        debug!("ws: Received text message: {:?}", msg);
                                        let request: WSRequest = match serde_json::from_str(&msg) {
                                            Ok(request) => request,
                                            Err(e) => {
                                                warn!("ws: Error parsing message: {:?}", e);
                                                break;
                                            }
                                        };

                                        if !resolve_and_respond(&mut socket, &state, request.did).await {
                                            break;
                                        }
                                    }
                                    Message::Binary(msg) => {
                                        debug!("ws: Received binary message: {:?}", msg);
                                        let request: WSRequest = match serde_json::from_slice(msg.as_ref()) {
                                            Ok(request) => request,
                                            Err(e) => {
                                                warn!("ws: Error parsing message: {:?}", e);
                                                break;
                                            }
                                        };

                                        if !resolve_and_respond(&mut socket, &state, request.did).await {
                                            break;
                                        }
                                    }
                                    Message::Ping(_) => {
                                        // Don't need to do anything, the library will automatically respond with a pong
                                    }
                                    Message::Pong(_) => {
                                        // Don't need to do anything
                                    }
                                    Message::Close(_) => {
                                        debug!("Received close message, closing connection");
                                        break;
                                    }
                                }
                            }
                            Err(err) => {
                                warn!("Error receiving message: {:?}", err);
                                continue;
                            }
                        }
                    } else {
                        debug!("Received None, closing connection");
                        break;
                    }
                }
            }
        }

        // We're done, close the connection
        state.stats().await.increment_ws_closed();

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
}
