use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, DIDMethod, ResolveResponse,
    networking::{WSRequest, WSResponse, WSResponseError, WSResponseType},
};
use agent_names::{AgentName, AgentNameResolver};
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
    handlers::{did_within_size_limit, fetch_webvh_log, resolve_with_timeout},
};

/// Build a WSResponse, fetching the raw DID log for WebVH DIDs.
async fn build_response(client: &reqwest::Client, response: ResolveResponse) -> WSResponseType {
    let (did_log, did_witness_log) = if response.method == DIDMethod::WEBVH {
        fetch_webvh_log(client, &response.did).await
    } else {
        (None, None)
    };

    WSResponseType::Response(Box::new(
        WSResponse::new(response.did.clone(), response.did_hash, response.doc)
            .with_logs(did_log, did_witness_log),
    ))
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
/// Route a request to the DID path or the agent name path.
///
/// An agent name request carries the name in `did` *and* in `agent_name`; a
/// server without agent name support simply never sees the latter and treats the
/// name as a DID, which fails cleanly.
async fn dispatch_request(socket: &mut WebSocket, state: &SharedData, request: WSRequest) -> bool {
    match request.agent_name {
        Some(name) => resolve_agent_name_and_respond(socket, state, name).await,
        None => resolve_and_respond(socket, state, request.did).await,
    }
}

/// Resolve an agent name to a DID **and** its document, in one exchange.
///
/// The response's `hash` is the hash of the **name as sent**, not of the
/// resolved DID: the client registered its waiter under that hash, so anything
/// else leaves the caller waiting out its timeout. `did` carries the resolved
/// DID, and `agent_name` echoes the name.
///
/// The client re-verifies `alsoKnownAs` against the document itself — this
/// server is a cache, not a trust anchor — so no verification is claimed here.
async fn resolve_agent_name_and_respond(
    socket: &mut WebSocket,
    state: &SharedData,
    name: String,
) -> bool {
    let name_hash = DIDCacheClient::hash_did(&name);

    let fail = |error: String| WSResponseType::Error(WSResponseError::new(&name, name_hash, error));

    if name.len() > state.max_did_size {
        state.stats().await.increment_agent_name_error();
        return send_response(
            socket,
            &fail(format!(
                "Agent name exceeds maximum length of {} bytes",
                state.max_did_size
            )),
        )
        .await;
    }

    let Some(resolver) = state.agent_name_resolver.as_ref() else {
        state.stats().await.increment_agent_name_error();
        return send_response(
            socket,
            &fail("Agent name resolution is not enabled on this server".to_string()),
        )
        .await;
    };

    let parsed = match AgentName::parse(&name) {
        Ok(parsed) => parsed,
        Err(e) => {
            state.stats().await.increment_agent_name_error();
            return send_response(socket, &fail(e.to_string())).await;
        }
    };

    // Same outbound-fetch ceiling as the HTTP endpoint: shed rather than queue.
    let Ok(_permit) = state.agent_name_permits.try_acquire() else {
        state.stats().await.increment_agent_name_error();
        warn!("ws: shedding agent name lookup '{parsed}': outbound fetch ceiling reached");
        return send_response(
            socket,
            &fail("Too many agent name lookups in flight; retry shortly".to_string()),
        )
        .await;
    };

    let did = match tokio::time::timeout(state.resolve_timeout, resolver.resolve(&parsed)).await {
        Ok(Some(Ok(did))) => did,
        Ok(Some(Err(e))) => {
            state.stats().await.increment_agent_name_error();
            return send_response(socket, &fail(e.to_string())).await;
        }
        Ok(None) => {
            state.stats().await.increment_agent_name_error();
            return send_response(
                socket,
                &fail(format!("No resolver could resolve '{parsed}'")),
            )
            .await;
        }
        Err(_elapsed) => {
            state.stats().await.increment_agent_name_error();
            return send_response(socket, &fail("Timed out resolving agent name".to_string()))
                .await;
        }
    };

    // Now resolve that DID exactly as a normal request would.
    match resolve_with_timeout(&state.resolver, state.resolve_timeout, &did).await {
        Ok(response) => {
            {
                let mut stats = state.stats().await;
                stats.increment_agent_name_success();
                stats.increment_resolver_success();
                if response.cache_hit {
                    stats.increment_cache_hit();
                }
                stats.increment_did_method_success(response.method.clone());
            }
            let (did_log, did_witness_log) = if response.method == DIDMethod::WEBVH {
                fetch_webvh_log(&state.webvh_client, &response.did).await
            } else {
                (None, None)
            };
            let message = WSResponseType::Response(Box::new(
                WSResponse::new(response.did.clone(), name_hash, response.doc)
                    .with_logs(did_log, did_witness_log)
                    .with_agent_name(Some(parsed.as_str().to_string())),
            ));
            send_response(socket, &message).await
        }
        Err(e) => {
            state.stats().await.increment_agent_name_error();
            send_response(socket, &fail(e.to_string())).await
        }
    }
}

async fn resolve_and_respond(socket: &mut WebSocket, state: &SharedData, did: String) -> bool {
    if !did_within_size_limit(&did, state.max_did_size) {
        let hash = DIDCacheClient::hash_did(&did);
        warn!("ws: rejecting oversized DID ({} bytes)", did.len());
        state.stats().await.increment_resolver_error();
        let message = WSResponseType::Error(WSResponseError::new(
            did,
            hash,
            format!("DID exceeds maximum length of {} bytes", state.max_did_size),
        ));
        return send_response(socket, &message).await;
    }

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
            let message = build_response(&state.webvh_client, response).await;
            send_response(socket, &message).await
        }
        Err(e) => {
            // Couldn't resolve the DID (or timed out), send an error back.
            let hash = DIDCacheClient::hash_did(&did);
            warn!("Couldn't resolve DID: ({did}) Reason: {e}");
            state.stats().await.increment_resolver_error();
            let message = WSResponseType::Error(WSResponseError::new(did, hash, e.to_string()));
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

    // Bound incoming frames so a crafted client can't buffer huge messages
    // before we even parse them. A DID request is tiny; size it to the DID
    // limit plus envelope overhead.
    let max_message_size = state.max_did_size.saturating_add(1024);
    let ws = ws
        .max_message_size(max_message_size)
        .max_frame_size(max_message_size);
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

                                        if !dispatch_request(&mut socket, &state, request).await {
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

                                        if !dispatch_request(&mut socket, &state, request).await {
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
