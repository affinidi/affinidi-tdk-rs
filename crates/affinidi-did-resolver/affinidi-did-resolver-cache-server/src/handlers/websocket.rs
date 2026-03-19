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

use crate::SharedData;

/// For did:webvh DIDs, fetch the raw DID log (did.jsonl) from the source HTTP endpoint.
/// This log is sent alongside the resolved document so clients can independently
/// verify the cryptographic chain, preventing a compromised cache server from
/// serving tampered DID documents.
async fn fetch_webvh_log(did: &str) -> (Option<String>, Option<String>) {
    let parsed_url = match didwebvh_rs::url::WebVHURL::parse_did_url(did) {
        Ok(url) => url,
        Err(e) => {
            warn!("Failed to parse WebVH DID URL for log fetch: {e}");
            return (None, None);
        }
    };

    let log_url = match parsed_url.get_http_url(Some("did.jsonl")) {
        Ok(url) => url,
        Err(e) => {
            warn!("Failed to construct log URL for WebVH DID: {e}");
            return (None, None);
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create HTTP client for WebVH log fetch: {e}");
            return (None, None);
        }
    };

    let did_log = match client.get(log_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.text().await {
            Ok(text) => Some(text),
            Err(e) => {
                warn!("Failed to read WebVH log response body: {e}");
                None
            }
        },
        Ok(resp) => {
            warn!("WebVH log fetch returned HTTP {}: {}", resp.status(), did);
            None
        }
        Err(e) => {
            warn!("Failed to fetch WebVH log for {}: {e}", did);
            None
        }
    };

    // Fetch witness proofs if log was successfully retrieved
    let did_witness_log = if did_log.is_some() {
        let witness_url = match parsed_url.get_http_url(Some("did-witness.json")) {
            Ok(url) => url,
            Err(_) => return (did_log, None),
        };
        match client.get(witness_url).send().await {
            Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
            _ => None,
        }
    } else {
        None
    };

    (did_log, did_witness_log)
}

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

                                        match state.resolver.resolve(&request.did).await {
                                            Ok(response) => {
                                                let mut stats = state.stats().await;
                                                stats.increment_resolver_success();
                                                if response.cache_hit { stats.increment_cache_hit();}
                                                stats.increment_did_method_success(response.method.clone());
                                                drop(stats);
                                                debug!("resolved DID: ({}) cache_hit?({})", response.did, response.cache_hit);
                                                let message = build_response(response).await;
                                                if let Err(e) = socket.send(Message::Text(serde_json::to_string(&message).unwrap().into())).await {
                                                    warn!("ws: Error sending response: {:?}", e);
                                                    break;
                                                } else {
                                                    debug!("Sent response: {:?}", message);
                                                }
                                            }
                                            Err(e) => {
                                                // Couldn't resolve the DID, send an error back
                                                let hash = DIDCacheClient::hash_did(&request.did);
                                                warn!("Couldn't resolve DID: ({}) Reason: {}", &request.did, e);
                                                state.stats().await.increment_resolver_error();
                                                if let Err(e) = socket.send(Message::Text(serde_json::to_string(&WSResponseType::Error(WSResponseError {did: request.did, hash, error: e.to_string()})).unwrap().into())).await {
                                                    warn!("ws: Error sending error response: {:?}", e);
                                                    break;
                                                }
                                            }
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

                                        match state.resolver.resolve(&request.did).await {
                                            Ok(response) => {
                                                let mut stats = state.stats().await;
                                                stats.increment_resolver_success();
                                                if response.cache_hit { stats.increment_cache_hit();}
                                                stats.increment_did_method_success(response.method.clone());
                                                drop(stats);
                                                debug!("resolved DID: ({}) cache_hit?({})", response.did, response.cache_hit);
                                                let message = build_response(response).await;
                                                if let Err(e) = socket.send(Message::Text(serde_json::to_string(&message).unwrap().into())).await {
                                                    warn!("ws: Error sending response: {:?}", e);
                                                    break;
                                                } else {
                                                    debug!("Sent response: {:?}", message);
                                                }
                                            }
                                            Err(e) => {
                                                // Couldn't resolve the DID, send an error back
                                                let hash = DIDCacheClient::hash_did(&request.did);
                                                warn!("Couldn't resolve DID: ({}) Reason: {}", &request.did, e);
                                                state.stats().await.increment_resolver_error();
                                                if let Err(e) = socket.send(Message::Text(serde_json::to_string(&WSResponseType::Error(WSResponseError {did: request.did, hash, error: e.to_string()})).unwrap().into())).await {
                                                    warn!("ws: Error sending error response: {:?}", e);
                                                    break;
                                                }
                                            }
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
