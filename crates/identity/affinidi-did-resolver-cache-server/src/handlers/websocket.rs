use affinidi_did_resolver_cache_sdk::{
    DIDCacheClient, DIDMethod, ResolveResponse,
    networking::{WSRequest, WSResponse, WSResponseError, WSResponseType},
};
use affinidi_rate_limit::TooManyRequests;
use agent_names::{AgentName, AgentNameResolver};
use axum::{
    Extension,
    extract::{
        ConnectInfo, State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket, close_code},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use std::net::{IpAddr, SocketAddr};
use tracing::{Instrument, debug, info, span, warn};

use crate::{
    SharedData, WebvhLogCache,
    handlers::{did_within_size_limit, fetch_webvh_log, resolve_with_timeout},
    limits::{ConnectionRefused, ConnectionSlot},
};

/// Build a WSResponse, fetching the raw DID log for WebVH DIDs.
async fn build_response(
    client: &reqwest::Client,
    cache: Option<&WebvhLogCache>,
    response: ResolveResponse,
) -> WSResponseType {
    let (did_log, did_witness_log) = if response.method == DIDMethod::WEBVH {
        fetch_webvh_log(client, cache, response.cache_hit, &response.did).await
    } else {
        (None, None)
    };

    WSResponseType::Response(Box::new(
        WSResponse::new(response.did.clone(), response.did_hash, response.doc)
            .with_logs(did_log, did_witness_log),
    ))
}

/// Serialize and send a WS response. Returns `false` if the connection should
/// be closed (serialization failure, send error, or a send that did not
/// complete within the configured send timeout). Never panics.
async fn send_response(
    socket: &mut WebSocket,
    state: &SharedData,
    message: &WSResponseType,
) -> bool {
    let text = match serde_json::to_string(message) {
        Ok(text) => text,
        Err(e) => {
            warn!("ws: failed to serialize response, closing connection: {e:?}");
            return false;
        }
    };
    let send_timeout = state.ws_limits.send_timeout;
    match tokio::time::timeout(send_timeout, socket.send(Message::Text(text.into()))).await {
        Ok(Ok(())) => {
            debug!("Sent response: {message:?}");
            true
        }
        Ok(Err(e)) => {
            warn!("ws: Error sending response: {e:?}");
            false
        }
        Err(_elapsed) => {
            warn!(
                "ws: response not sent within {}s, closing connection",
                send_timeout.as_secs()
            );
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
            state,
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
            state,
            &fail("Agent name resolution is not enabled on this server".to_string()),
        )
        .await;
    };

    let parsed = match AgentName::parse(&name) {
        Ok(parsed) => parsed,
        Err(e) => {
            state.stats().await.increment_agent_name_error();
            return send_response(socket, state, &fail(e.to_string())).await;
        }
    };

    // Same outbound-fetch ceiling as the HTTP endpoint: shed rather than queue.
    let Ok(_permit) = state.agent_name_permits.try_acquire() else {
        state.stats().await.increment_agent_name_error();
        warn!("ws: shedding agent name lookup '{parsed}': outbound fetch ceiling reached");
        return send_response(
            socket,
            state,
            &fail("Too many agent name lookups in flight; retry shortly".to_string()),
        )
        .await;
    };

    let did = match tokio::time::timeout(state.resolve_timeout, resolver.resolve(&parsed)).await {
        Ok(Some(Ok(did))) => did,
        Ok(Some(Err(e))) => {
            state.stats().await.increment_agent_name_error();
            return send_response(socket, state, &fail(e.to_string())).await;
        }
        Ok(None) => {
            state.stats().await.increment_agent_name_error();
            return send_response(
                socket,
                state,
                &fail(format!("No resolver could resolve '{parsed}'")),
            )
            .await;
        }
        Err(_elapsed) => {
            state.stats().await.increment_agent_name_error();
            return send_response(
                socket,
                state,
                &fail("Timed out resolving agent name".to_string()),
            )
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
                fetch_webvh_log(
                    &state.webvh_client,
                    state.webvh_log_cache.as_deref(),
                    response.cache_hit,
                    &response.did,
                )
                .await
            } else {
                (None, None)
            };
            let message = WSResponseType::Response(Box::new(
                WSResponse::new(response.did.clone(), name_hash, response.doc)
                    .with_logs(did_log, did_witness_log)
                    .with_agent_name(Some(parsed.as_str().to_string())),
            ));
            send_response(socket, state, &message).await
        }
        Err(e) => {
            state.stats().await.increment_agent_name_error();
            send_response(socket, state, &fail(e.to_string())).await
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
        return send_response(socket, state, &message).await;
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
            let message = build_response(
                &state.webvh_client,
                state.webvh_log_cache.as_deref(),
                response,
            )
            .await;
            send_response(socket, state, &message).await
        }
        Err(e) => {
            // Couldn't resolve the DID (or timed out), send an error back.
            let hash = DIDCacheClient::hash_did(&did);
            warn!("Couldn't resolve DID: ({did}) Reason: {e}");
            state.stats().await.increment_resolver_error();
            let message = WSResponseType::Error(WSResponseError::new(did, hash, e.to_string()));
            send_response(socket, state, &message).await
        }
    }
}

/// Charge a request message to `client`'s rate-limit bucket, the one its HTTP
/// requests use, then handle it. A refused message is answered with an error
/// for that request and the connection stays open. Returns `false` if the
/// connection should be closed.
async fn handle_request(
    socket: &mut WebSocket,
    state: &SharedData,
    client: IpAddr,
    request: WSRequest,
) -> bool {
    if let Err(TooManyRequests { retry_after_secs }) = state.rate_limiter.charge(client) {
        if state.rate_limiter.first_refusal_in_window(&client) {
            warn!(client = %client, "ws: client over the rate limit; refusing its requests until its bucket refills");
        }
        let hash = DIDCacheClient::hash_did(&request.did);
        let message = WSResponseType::Error(WSResponseError::new(
            request.did,
            hash,
            format!("Too many requests; retry after {retry_after_secs}s"),
        ));
        return send_response(socket, state, &message).await;
    }
    dispatch_request(socket, state, request).await
}

/// Admit a WebSocket connection and switch protocols.
///
/// The client is worked out as the rate limiter does (the socket peer, or the
/// address a trusted proxy reports), and the connection is refused before the
/// upgrade when the server-wide or per-client connection limit is reached.
pub async fn websocket_handler(
    State(state): State<SharedData>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let _span = span!(tracing::Level::DEBUG, "websocket_handler");

    // Without the peer address the connection cannot be counted against its
    // client, so it is refused. The server always attaches it.
    let Some(Extension(ConnectInfo(peer))) = peer else {
        warn!("ws: no client address; refusing the connection");
        return (StatusCode::FORBIDDEN, "No client address").into_response();
    };
    let client = match state.client_ip_extractor.client_key(peer.ip(), &headers) {
        Ok(client) => client,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let slot = match state.ws_limits.try_open(client) {
        Ok(slot) => slot,
        Err(refused) => {
            warn!(client = %client, "ws: connection refused: {refused}");
            let status = match refused {
                ConnectionRefused::ServerFull => StatusCode::SERVICE_UNAVAILABLE,
                ConnectionRefused::ClientFull => StatusCode::TOO_MANY_REQUESTS,
            };
            return (status, [(header::RETRY_AFTER, "5")], refused.to_string()).into_response();
        }
    };

    // Bound incoming messages and frames so a client can't make the server
    // buffer large messages before they are even parsed.
    let max_message_size = state.ws_limits.max_message_size;
    let ws = ws
        .max_message_size(max_message_size)
        .max_frame_size(max_message_size);
    async move { ws.on_upgrade(move |socket| handle_socket(socket, state, client, slot)) }
        .instrument(_span)
        .await
}

/// WebSocket state machine. This is spawned per connection; `_slot` holds its
/// place in the connection limits until the connection ends.
async fn handle_socket(
    mut socket: WebSocket,
    state: SharedData,
    client: IpAddr,
    _slot: ConnectionSlot,
) {
    let _span = span!(tracing::Level::DEBUG, "handle_socket", client = %client);
    async move {
        state.stats().await.increment_ws_opened();
        info!("Websocket connection established");

        let idle_timeout = state.ws_limits.idle_timeout;
        loop {
            // Any frame from the client, a ping included, counts as activity.
            let received = match tokio::time::timeout(idle_timeout, socket.recv()).await {
                Ok(received) => received,
                Err(_elapsed) => {
                    debug!(
                        "ws: nothing received for {}s, closing connection",
                        idle_timeout.as_secs()
                    );
                    let close = Message::Close(Some(CloseFrame {
                        code: close_code::AWAY,
                        reason: "idle".into(),
                    }));
                    let _ = tokio::time::timeout(state.ws_limits.send_timeout, socket.send(close))
                        .await;
                    break;
                }
            };

            let msg = match received {
                Some(Ok(msg)) => msg,
                Some(Err(err)) => {
                    // Errors from the WebSocket stream (an oversized message
                    // among them) are not recoverable on this connection.
                    warn!("ws: Error receiving message, closing connection: {err:?}");
                    break;
                }
                None => {
                    debug!("Received None, closing connection");
                    break;
                }
            };

            let request: Result<WSRequest, _> = match msg {
                Message::Text(msg) => {
                    debug!("ws: Received text message: {:?}", msg);
                    serde_json::from_str(&msg)
                }
                Message::Binary(msg) => {
                    debug!("ws: Received binary message: {:?}", msg);
                    serde_json::from_slice(msg.as_ref())
                }
                // Pongs to pings are sent by the library.
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => {
                    debug!("Received close message, closing connection");
                    break;
                }
            };
            let request = match request {
                Ok(request) => request,
                Err(e) => {
                    warn!("ws: Error parsing message: {:?}", e);
                    break;
                }
            };

            if !handle_request(&mut socket, &state, client, request).await {
                break;
            }
        }

        // We're done, close the connection
        state.stats().await.increment_ws_closed();

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
}
