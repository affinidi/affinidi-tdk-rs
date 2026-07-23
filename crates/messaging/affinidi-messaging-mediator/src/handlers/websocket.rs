use crate::common::metrics::names::ACTIVE_WEBSOCKET_CONNECTIONS;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
#[cfg(feature = "tsp")]
use crate::messages::inbound::handle_inbound_tsp;
use crate::{
    SharedData,
    common::config::{CorsOriginPolicy, origin_matches},
    common::jwt_auth::{AuthError, authenticate_token},
    common::session::Session,
    messages::inbound::handle_inbound,
    tasks::websocket_streaming::{
        QueuedCommand, StreamingUpdate, StreamingUpdateState, WS_CHANNEL_SLOTS, WebSocketCommands,
    },
};
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
#[cfg(feature = "tsp")]
use affinidi_messaging_mediator_common::store::DeletionAuthority;
use affinidi_messaging_mediator_common::store::StatCounter;
#[cfg(feature = "tsp")]
use affinidi_messaging_mediator_common::types::messages::FetchOptions;
#[cfg(feature = "didcomm")]
use affinidi_messaging_sdk::messages::problem_report::ProblemReport;
use affinidi_messaging_sdk::messages::problem_report::{ProblemReportScope, ProblemReportSorter};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
#[cfg(feature = "tsp")]
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use dashmap::DashMap;
use http::{HeaderMap, HeaderValue, StatusCode, header::ORIGIN, header::SEC_WEBSOCKET_PROTOCOL};
#[cfg(feature = "didcomm")]
use serde_json::json;
#[cfg(feature = "tsp")]
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{Instrument, debug, info, span, warn};
#[cfg(feature = "didcomm")]
use uuid::Uuid;

/// Subprotocol prefix used to carry the bearer JWT through the
/// `Sec-WebSocket-Protocol` request header.
///
/// Browsers cannot set an `Authorization` header on `new WebSocket(url,
/// protocols)`, but they *can* offer subprotocols. By convention the
/// browser offers a single entry of the form `bearer.<jwt>` (optionally
/// alongside genuine application subprotocols). The server detects the
/// entry carrying this prefix, strips the literal 7-character `bearer.`
/// prefix, and treats the remainder as the raw JWT — identical to the
/// token a native client would send in the `Authorization` header.
///
/// A *prefix strip* (not a `.`-split) is deliberate: a JWT is three
/// base64url segments joined by `.`, so splitting on `.` would be
/// ambiguous. Every JWT character (`[A-Za-z0-9-_]` plus `.`) is a valid
/// RFC 6455 subprotocol token char, so no extra encoding is needed.
///
/// Browser client usage:
/// ```js
/// new WebSocket("wss://…/mediator/v1/ws", ["bearer." + accessToken]);
/// ```
const WS_BEARER_SUBPROTOCOL_PREFIX: &str = "bearer.";

/// Extract the raw JWT from a `bearer.<jwt>` entry in the client's
/// requested WebSocket subprotocols, returning the first match.
///
/// Returns `None` when no entry carries the `bearer.` prefix or the
/// remainder is empty. Uses [`str::strip_prefix`] (not `split`) so the
/// `.` separators inside the JWT are preserved verbatim.
fn extract_bearer_subprotocol<'a, I>(protocols: I) -> Option<String>
where
    I: IntoIterator<Item = &'a HeaderValue>,
{
    protocols.into_iter().find_map(|p| {
        p.to_str().ok().and_then(|header_val| {
            // RFC 6455: subprotocols may be comma-separated in a single header value
            header_val.split(',').find_map(|s| {
                s.trim()
                    .strip_prefix(WS_BEARER_SUBPROTOCOL_PREFIX)
                    .filter(|token| !token.is_empty())
                    .map(str::to_string)
            })
        })
    })
}

/// The subprotocols the server may safely echo back in the 101
/// response: every requested entry that is **not** a bearer token.
///
/// Reflecting a `bearer.<jwt>` entry would leak the secret token in the
/// `Sec-WebSocket-Protocol` response header, so those entries are
/// filtered out here and never offered to [`WebSocketUpgrade::protocols`].
fn app_subprotocols<'a, I>(protocols: I) -> Vec<String>
where
    I: IntoIterator<Item = &'a HeaderValue>,
{
    // RFC 6455: subprotocols may be comma-separated in a single header value
    protocols
        .into_iter()
        .filter_map(|p| p.to_str().ok())
        .flat_map(|header_val| header_val.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with(WS_BEARER_SUBPROTOCOL_PREFIX))
        .map(str::to_string)
        .collect()
}

/// Whether a WebSocket upgrade carrying this `Origin` header is allowed
/// by the configured CORS policy.
///
/// WebSocket upgrades aren't subject to CORS preflight, but browsers
/// still send an `Origin` header on them. This mirrors the REST CORS
/// allowlist ([`CorsOriginPolicy`]) as defence-in-depth: a browser from
/// a non-allowlisted origin is refused even if it somehow holds a valid
/// token. Native clients send no `Origin` header and are always allowed
/// — for them the JWT is the only (and sufficient) gate.
fn ws_origin_allowed(policy: &CorsOriginPolicy, origin: Option<&HeaderValue>) -> bool {
    match origin {
        // No Origin ⇒ not a browser cross-origin context (native client).
        None => true,
        Some(origin) => match policy {
            CorsOriginPolicy::Any => true,
            // Reuse the *same* matcher the REST CORS layer uses so the
            // two enforcement points (incl. `*.suffix` wildcards) can't
            // drift apart.
            CorsOriginPolicy::List(matchers) => origin_matches(matchers, origin),
            // No cross-origin browser access configured ⇒ refuse any
            // request that announces an Origin.
            CorsOriginPolicy::None => false,
        },
    }
}

/// Handles the switching of the protocol to a websocket connection.
///
/// ACL_MODE: Requires LOCAL access.
///
/// Authentication accepts the JWT from either channel, in priority
/// order:
/// 1. `Authorization: Bearer <jwt>` request header — the existing path
///    used by native clients (e.g. the Rust SDK). Unchanged.
/// 2. The `bearer.<jwt>` entry of the `Sec-WebSocket-Protocol` request
///    header — the browser-friendly path (browsers can't set request
///    headers on a WebSocket upgrade). See
///    [`WS_BEARER_SUBPROTOCOL_PREFIX`].
///
/// Both channels validate the token identically via
/// [`authenticate_token`]; the resulting [`Session`] (and therefore the
/// per-connection JWT-expiry timeout enforced in [`handle_socket`]) is
/// the same regardless of how the token arrived. If neither channel
/// yields a valid token the upgrade is rejected, exactly as before.
pub async fn websocket_handler(
    State(state): State<SharedData>,
    auth_header: Option<TypedHeader<Authorization<Bearer>>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    // 0. Defence-in-depth Origin check. WebSocket upgrades aren't
    //    subject to CORS, but browsers send an `Origin` header — refuse
    //    cross-origin browsers outside the configured allowlist. Native
    //    clients send no Origin and pass straight through.
    let origin = headers.get(ORIGIN);
    if !ws_origin_allowed(&state.config.security.cors_origins, origin) {
        warn!(
            ?origin,
            "WebSocket upgrade rejected: Origin not permitted by CORS policy"
        );
        return (StatusCode::FORBIDDEN, "origin not allowed").into_response();
    }

    // 1. Resolve the JWT: Authorization header first (native clients),
    //    then the Sec-WebSocket-Protocol subprotocol (browsers).
    let token = if let Some(TypedHeader(Authorization(bearer))) = &auth_header {
        Some(bearer.token().to_string())
    } else {
        extract_bearer_subprotocol(headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter())
    };

    let Some(token) = token else {
        warn!(
            "WebSocket upgrade rejected: no bearer token in Authorization header or Sec-WebSocket-Protocol"
        );
        return AuthError::MissingCredentials.into_response();
    };

    // 2. Validate the token → Session (identical checks for both paths).
    let session = match authenticate_token(&state, &token).await {
        Ok(session) => session,
        Err(e) => return e.into_response(),
    };

    let _span = span!(
        tracing::Level::INFO,
        "websocket_handler",
        session = session.session_id
    );

    // 3. ACL Check (websockets only work on local DID's).
    if !session.acls.get_local() {
        let error: AppError = MediatorError::problem(
            40,
            session.session_id,
            None,
            ProblemReportSorter::Error,
            ProblemReportScope::Protocol,
            "authorization.local",
            "DID isn't local to the mediator",
            vec![],
            StatusCode::FORBIDDEN,
        )
        .into();

        return error.into_response();
    }

    // 4. Echo back only genuine application subprotocols (if any) — and
    //    NEVER the `bearer.<jwt>` entry, which would leak the token in
    //    the 101 response header. When the client offered only the
    //    bearer entry, no subprotocol is selected and the response
    //    carries no `Sec-WebSocket-Protocol` header (RFC 6455 permits
    //    this; browsers accept it).
    let app_protocols = app_subprotocols(headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter());

    // A client opts into raw-TSP WebSocket delivery by offering a `tsp`
    // subprotocol alongside `bearer.<jwt>`. The `tsp` marker is echoed back to
    // the client via the `app_protocols` path below (it's a genuine app
    // subprotocol, not the bearer entry), so the client learns the mode was
    // accepted from the 101 response's `Sec-WebSocket-Protocol` header.
    #[cfg(feature = "tsp")]
    let tsp_mode = app_protocols.iter().any(|p| p == "tsp" || p == "tsp-ack");

    // `tsp-ack` opts into DELETE-TO-ACK delivery. Plain `tsp` keeps the
    // original delete-on-send contract, which is at-most-once past the socket
    // write: the frame is deleted as soon as it has been handed to the local
    // sink, so a connection that dies before the peer reads it loses the
    // message with nothing left to redeliver. That is fine for a liveness probe
    // and wrong for anything that matters.
    //
    // In `tsp-ack` mode the mediator sends and keeps. The client acknowledges
    // by deleting the message through the ordinary authenticated delete path
    // once it has taken the frame — the id is `sha256` of the stored body,
    // which is exactly the bytes on the wire, so the client can derive it
    // without the mediator sending ids and without any change to the frame
    // format. An un-acked message is simply still there on the next connect.
    //
    // Opt-in on purpose: flipping every client at once would trade silent loss
    // for silent duplication, since a client that never acks would be
    // redelivered its whole inbox on every reconnect.
    #[cfg(feature = "tsp")]
    let tsp_ack_mode = app_protocols.iter().any(|p| p == "tsp-ack");

    // The echo has to be a HONEST capability signal, and by default it isn't:
    // the offered list is just the client's own list reflected back, so a
    // mediator that has never heard of a subprotocol still echoes it. A client
    // asking for `tsp-ack` against an older mediator would therefore be told
    // "yes" and silently get delete-on-send — the exact silent downgrade
    // delete-to-ack exists to prevent.
    //
    // Fixed by ordering. Clients offer `tsp` BEFORE `tsp-ack`, and axum selects
    // the first client-requested protocol that the server also lists:
    //   * older mediator — reflects the client's list, so it selects the
    //     client's first entry, `tsp`. The client sees no ack support. Correct.
    //   * this mediator — narrows the offer to `tsp-ack` alone, so that is what
    //     gets selected despite being second. The client sees ack support, and
    //     only a mediator that implements it can produce that answer.
    #[cfg(feature = "tsp")]
    let app_protocols = if tsp_ack_mode {
        vec!["tsp-ack".to_string()]
    } else {
        app_protocols
    };

    let ws = if app_protocols.is_empty() {
        ws
    } else {
        ws.protocols(app_protocols)
    };

    // 5. Enforce the configured `ws_size` cap at the tungstenite layer so
    //    oversized frames are rejected during framing instead of being
    //    buffered in full and only checked after `socket.recv()` returns.
    let ws_size = state.config.limits.ws_size;
    let ws = ws.max_message_size(ws_size).max_frame_size(ws_size);

    #[cfg(feature = "tsp")]
    {
        async move {
            ws.on_upgrade(move |socket| {
                handle_socket(socket, state, session, tsp_mode, tsp_ack_mode)
            })
        }
        .instrument(_span)
        .await
    }
    #[cfg(not(feature = "tsp"))]
    {
        async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
            .instrument(_span)
            .await
    }
}

/// Releases a DID's reserved per-DID WebSocket slot on drop, so the count is
/// decremented on *every* `handle_socket` return path (including the early
/// returns before the main loop). The entry is removed once it reaches zero
/// so the registry doesn't accumulate idle DIDs.
struct PerDidConnectionGuard {
    registry: Arc<DashMap<String, u32>>,
    did_hash: String,
}

impl Drop for PerDidConnectionGuard {
    fn drop(&mut self) {
        if let Some(mut count) = self.registry.get_mut(&self.did_hash) {
            *count = count.saturating_sub(1);
        }
        self.registry
            .remove_if(&self.did_hash, |_, &count| count == 0);
    }
}

/// RFC 6455 close codes the mediator uses, so clients learn *why* a socket was
/// closed instead of seeing a bare close.
mod close_code {
    /// Normal closure (graceful end / client-initiated).
    pub const NORMAL: u16 = 1000;
    /// Endpoint going away — peer unresponsive or the stream ended.
    pub const GOING_AWAY: u16 = 1001;
    /// Policy violation — auth expired, per-DID cap, duplicate displacement.
    pub const POLICY: u16 = 1008;
    /// Unexpected server-side condition.
    pub const SERVER_ERROR: u16 = 1011;
    /// Transient capacity limit — try again later.
    pub const TRY_AGAIN_LATER: u16 = 1013;
}

/// Build a close message carrying an RFC 6455 code + human-readable reason.
fn close_with(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

/// WebSocket state machine. This is spawned per connection.
async fn handle_socket(
    mut socket: WebSocket,
    state: SharedData,
    session: Session,
    #[cfg(feature = "tsp")] tsp_mode: bool,
    #[cfg(feature = "tsp")] tsp_ack_mode: bool,
) {
    let _span = span!(
        tracing::Level::INFO,
        "handle_socket",
        session = session.session_id
    );
    async move {
        // Enforce the global connection limit.
        let current = state.active_websocket_count.fetch_add(1, Ordering::Relaxed);
        if current >= state.config.limits.max_websocket_connections {
            state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
            warn!("WebSocket connection limit reached ({}/{})", current, state.config.limits.max_websocket_connections);
            let _ = socket
                .send(close_with(
                    close_code::TRY_AGAIN_LATER,
                    "server connection limit reached",
                ))
                .await;
            return;
        }

        // Enforce the per-DID connection cap (0 = unlimited). Reserve the slot
        // immediately and bind a guard so it's released on every return path;
        // then reject if this DID is over its cap (the global slot reserved
        // above is backed out explicitly, the per-DID slot by the guard).
        let per_did_count = {
            let mut entry = state
                .ws_connections_per_did
                .entry(session.did_hash.clone())
                .or_insert(0);
            *entry += 1;
            *entry
        };
        let _per_did_guard = PerDidConnectionGuard {
            registry: state.ws_connections_per_did.clone(),
            did_hash: session.did_hash.clone(),
        };
        let per_did_cap = state.config.limits.max_websocket_connections_per_did;
        if per_did_cap != 0 && per_did_count as usize > per_did_cap {
            state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
            warn!(
                "Per-DID WebSocket connection limit reached for {} ({}/{})",
                session.did_hash, per_did_count, per_did_cap
            );
            let _ = socket
                .send(close_with(
                    close_code::POLICY,
                    "per-DID connection limit reached",
                ))
                .await;
            return;
        }

        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).increment(1.0);

        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, mut rx): (Sender<QueuedCommand>, Receiver<QueuedCommand>) =
            mpsc::channel(WS_CHANNEL_SLOTS);
        if let Some(streaming) = &state.streaming_task {

            let start = StreamingUpdate {
                did_hash: session.did_hash.clone(),
                state: StreamingUpdateState::Register {
                    channel: tx,
                    session_id: session.session_id.clone(),
                    did: session.did.clone(),
                },
            };
            match streaming.channel.send(start).await {
                Ok(_) => {
                    debug!("Sent start message to streaming task");
                }
                Err(e) => {
                    warn!("Error sending start message to streaming task: {:?}", e);
                    return;
                }
            }

            // Raw-TSP mode is live by construction — enable it here.
            //
            // `Register` alone leaves the client in `StreamingClientState::
            // Registered` ("has a socket but has not enabled live delivery"),
            // and only `Start` promotes it to `Live`. The DIDComm client gets
            // there by sending `messagepickup/3.0/live-delivery-change`; a
            // raw-TSP socket has no such message — it carries binary TSP frames
            // and nothing else — so it stayed `Registered` forever. With the
            // client not live, `store_message` skips the streaming publish
            // entirely, so the `rx.recv()` re-drain arm below never fired and
            // the ONLY delivery this socket ever got was flush-on-connect.
            // Every frame that arrived after the socket came up was stored and
            // left sitting in the inbox: the sender saw a successful send and
            // the recipient heard nothing.
            //
            // Push delivery isn't an opt-in here the way it is for DIDComm —
            // it is the raw-TSP contract (flush-on-connect + delete-on-send),
            // so the socket declares itself live the moment it registers.
            #[cfg(feature = "tsp")]
            if tsp_mode {
                let live = StreamingUpdate {
                    did_hash: session.did_hash.clone(),
                    state: StreamingUpdateState::Start,
                };
                match streaming.channel.send(live).await {
                    Ok(_) => {
                        debug!("Raw-TSP socket: enabled live delivery");
                    }
                    Err(e) => {
                        warn!("Error enabling live delivery for raw-TSP socket: {:?}", e);
                        return;
                    }
                }
            }
        }

        let _ = state
            .database
            .stats_increment(StatCounter::WebsocketOpen, 1)
            .await;
        info!("Websocket connection established");

        // Set a timeout for the websocket connection for when the JWT Auth token expires
        let epoch = state.clock.unix_secs();
        if session.expires_at <= epoch {
            warn!("JWT access token has expired. Closing Session");
            let _ = socket
                .send(close_with(
                    close_code::POLICY,
                    "authentication token expired",
                ))
                .await;
            return;
        }
        let auth_timeout = tokio::time::sleep(Duration::from_secs(session.expires_at - epoch));
        tokio::pin!(auth_timeout);
        debug!(expires_in_secs = session.expires_at - epoch, "WebSocket auth timeout set");

        // Periodic ping to detect dead connections
        let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
        ping_interval.reset(); // Skip the immediate first tick

        // Sent-but-not-yet-acked message ids, for `tsp-ack` mode only.
        //
        // In ack mode the mediator no longer deletes on send, so every drain
        // re-fetches the same un-acked messages and would re-send them on each
        // live-delivery wake-up — turning "may see a duplicate after a
        // reconnect" into "sees duplicates constantly". This set is what makes
        // redelivery a *recovery* mechanism rather than the steady state:
        // within one connection a frame is sent once, and the set dies with the
        // connection, so a reconnect legitimately re-sends whatever was never
        // acked.
        //
        // Bounded implicitly: it only ever holds ids the inbox still contains,
        // and it is pruned against each completed drain, so client acks remove
        // entries. The inbox itself is capped by
        // `queued_receive_messages_hard` and message expiry.
        #[cfg(feature = "tsp")]
        let mut tsp_inflight: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Flush-on-connect for raw-TSP delivery: drain whatever is already queued
        // for this DID straight onto the socket before entering the live-delivery
        // loop. If the socket is already gone, exit cleanly.
        #[cfg(feature = "tsp")]
        if tsp_mode && drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight)
            .await
            .is_break() {
            if let Some(streaming) = &state.streaming_task {
                let stop = StreamingUpdate {
                    did_hash: session.did_hash.clone(),
                    state: StreamingUpdateState::Deregister {
                        session_id: session.session_id.clone(),
                    },
                };
                let _ = streaming.channel.send(stop).await;
            }
            state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
            metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).decrement(1.0);
            let _ = state
                .database
                .stats_increment(StatCounter::WebsocketClose, 1)
                .await;
            info!("Websocket connection closed during TSP flush-on-connect");
            return;
        }

        // Flag to prevent double deregistration
        // This can occur because in some situations the streaming-task will send a close message
        // due to duplicate channels. If we were to deregister on close in this scenario, we would
        // also deregister the new channel that is still in use.
        let mut already_deregistered_flag = false;
        // Why this socket ends up closing — surfaced in the final close frame.
        let mut close_reason: (u16, &'static str) = (close_code::NORMAL, "normal closure");
        loop {
            select! {
                _ = &mut auth_timeout => {
                    debug!("Auth Timeout reached");
                    close_reason = (close_code::POLICY, "authentication token expired");
                    break;
                }
                value = socket.recv() => {
                    match value { Some(msg) => {
                        if let Ok(msg) = msg {
                            match msg {
                                Message::Text(msg) => {
                                    if msg.len() > state.config.limits.ws_size {
                                        warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.limits.ws_size, msg.len());
                                        continue;
                                    }

                                    // Process the message, which also takes care of any storing and live-streaming of the message
                                    match handle_inbound(&state, &session, &msg).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            warn!("WebSocket inbound error: {}", e);

                                            // Send a problem report to the sender
                                            #[cfg(feature = "didcomm")]
                                            match e {
                                                MediatorError::MediatorError(_, _, msg_id, problem_report, _, log_message) => {
                                                    match  _package_problem_report(&state, &session, msg_id, *problem_report).await {
                                                        Ok(msg) => {
                                                            warn!(log_message);
                                                            if let Err(e) = socket.send(Message::Text(msg.into())).await {
                                                                warn!("Failed to send message to WebSocket client: {e}");
                                                            }
                                                        }
                                                        Err(e) => {
                                                            warn!("Error packaging problem report: {:?}", e);
                                                        }
                                                    }
                                                },
                                                _ => {
                                                    // This is a generic error, we don't need to send a problem report
                                                    warn!("Error processing message: {:?}", e);
                                                }
                                            }
                                            #[cfg(not(feature = "didcomm"))]
                                            warn!("Error processing message: {:?}", e);

                                            continue;
                                        }
                                    };
                                }
                                Message::Ping(_) => {
                                    // Don't need to do anything, the library will automatically respond with a pong
                                }
                                Message::Pong(_) => {
                                    // Don't need to do anything
                                }
                                Message::Binary(msg) => {
                                    if msg.len() > state.config.limits.ws_size {
                                        warn!("Error processing message, the size is too big. limit is {}, message size is {}", state.config.limits.ws_size, msg.len());
                                        continue;
                                    }

                                    // A binary frame leading with the TSP magic byte (0xF8) is a
                                    // TSP message; route it to the TSP handler. Other binary frames
                                    // are UTF-8-decoded and handled as DIDComm exactly as before.
                                    #[cfg(feature = "tsp")]
                                    if affinidi_tsp::is_tsp(&msg) {
                                        if let Err(e) = handle_inbound_tsp(&state, &session, &msg).await {
                                            warn!("WebSocket TSP inbound error: {}", e);
                                        }
                                        continue;
                                    }

                                    let msg = match String::from_utf8(msg.into()) {
                                        Ok(msg) => msg,
                                        Err(e) => {
                                            warn!("Error processing binary message: {:?}", e);
                                            continue;
                                        }
                                    };

                                    match handle_inbound(&state, &session, &msg).await {
                                        Ok(_) => {}
                                        Err(e) => {
                                            warn!("WebSocket inbound error: {}", e);
                                            continue;
                                        }
                                    };
                                }
                                Message::Close(_) => {
                                    debug!("Received close message, closing connection");
                                    break;
                                }
                            }
                        }
                    } _ => {
                        debug!("Received None, closing connection");
                        close_reason = (close_code::GOING_AWAY, "client disconnected");
                        break;
                    }}
                }
                _ = ping_interval.tick() => {
                    if let Err(e) = socket.send(Message::Ping(vec![].into())).await {
                        debug!("Failed to send WebSocket ping: {e}");
                        close_reason = (close_code::GOING_AWAY, "connection unresponsive");
                        break;
                    }
                }
                value = rx.recv() => {
                    if let Some(queued) = value {
                        // Destructuring drops `_permit` at the end of this arm,
                        // returning the message's bytes to the global send pool
                        // once it has been written to the socket.
                        match queued.cmd {
                            WebSocketCommands::Message(msg) => {
                                debug!("ws: Received message from streaming task");
                                // In raw-TSP mode the notification body carries no id we can
                                // delete by, so it's just a wake-up: re-drain the inbox (which
                                // re-fetches with ids, sends Binary, and deletes-on-send). The
                                // DIDComm path is unchanged — send the body as Text.
                                #[cfg(feature = "tsp")]
                                if tsp_mode {
                                    let _ = &msg; // body intentionally ignored in TSP mode
                                    if drain_tsp_inbox(&state, &session, &mut socket, tsp_ack_mode, &mut tsp_inflight)
            .await
            .is_break() {
                                        close_reason = (close_code::GOING_AWAY, "client disconnected");
                                        break;
                                    }
                                    continue;
                                }
                                if let Err(e) = socket.send(Message::Text(msg.into())).await {
                                    warn!("Failed to send message to WebSocket client: {e}");
                                }
                            },
                            WebSocketCommands::Close => {
                                #[cfg(feature = "didcomm")]
                                if let Ok(msg) =  _package_problem_report(&state, &session, None, _generate_duplicate_connection_problem_report()).await
                                    && let Err(e) = socket.send(Message::Text(msg.into())).await
                                {
                                    warn!("Failed to send message to WebSocket client: {e}");
                                }
                                debug!("Streaming task requested close (duplicate connection)");
                                already_deregistered_flag = true;
                                close_reason = (close_code::POLICY, "replaced by a newer connection");
                                break;
                            }
                        }
                    } else {
                        debug!("Received None from streaming task, closing connection");
                        close_reason = (close_code::SERVER_ERROR, "streaming task unavailable");
                        break;
                    }
                }
            }
        }

        // Remove this websocket and associated info from the streaming task
        if !already_deregistered_flag { // Skip if close initiated by the streaming task
            if let Some(streaming) = &state.streaming_task  {
                let stop = StreamingUpdate {
                    did_hash: session.did_hash.clone(),
                    state: StreamingUpdateState::Deregister {
                        session_id: session.session_id.clone(),
                    },
                };
                let _ = streaming.channel.send(stop).await;
            }
        }

        state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).decrement(1.0);

        // We're done, close the connection with the reason that ended the loop.
        if let Err(e) = socket
            .send(close_with(close_reason.0, close_reason.1))
            .await
        {
            debug!("Failed to send WebSocket close frame: {e}");
        }
        let _ = state
            .database
            .stats_increment(StatCounter::WebsocketClose, 1)
            .await;

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
}

/// Page size for the TSP inbox drain — reuses the same shape as
/// [`crate::tasks::websocket_streaming`]'s redelivery drain.
#[cfg(feature = "tsp")]
const TSP_DRAIN_PAGE: usize = 50;

/// Safety bound on how many messages a single TSP drain will push, so a
/// pathologically large inbox can't pin the socket loop. If hit, the
/// remainder is left for the next drain (the next live-delivery wake-up
/// re-fetches from the head of the inbox).
#[cfg(feature = "tsp")]
const TSP_DRAIN_MAX: usize = 1000;

/// Drain the recipient's undelivered inbox to a **raw TSP** WebSocket,
/// inline on the connection. Each stored message is decoded to its raw qb2
/// bytes and sent as a `Binary` frame; what happens next depends on the mode
/// the client negotiated at the upgrade.
///
/// ## `ack_mode = false` (subprotocol `tsp`) — delete-on-send, at-most-once
///
/// The socket write itself is treated as the ack: the message is deleted the
/// moment `send` returns. A successful `send` means the frame was accepted by
/// the local sink, **not** that the peer received it, so a connection that
/// drops between the write and the peer reading it loses the message with
/// nothing left to redeliver — the mediator has already forgotten it. This is
/// the historical behaviour and is kept for compatibility. It is appropriate
/// for a liveness probe and not for anything that matters.
///
/// (If the *send* fails, the socket is gone and the message and the rest of
/// the inbox are left intact for the next connection.)
///
/// ## `ack_mode = true` (subprotocol `tsp-ack`) — delete-to-ack, at-least-once
///
/// The mediator sends and keeps. The client acknowledges out of band, by
/// deleting the message through the ordinary authenticated delete path once it
/// has actually taken the frame; the id is `sha256` of the stored body, which
/// is exactly the bytes on the wire, so the client derives it without the
/// mediator sending ids and without any change to the frame format. A message
/// the client never acks is simply still in the inbox on the next connect and
/// is redelivered — so a consumer may see a duplicate, and must be idempotent,
/// which is the standard trade for not losing messages.
///
/// Un-acked messages are bounded by the same limits as any other queued
/// message (`queued_receive_messages_hard`, message expiry); nothing new can
/// grow without limit here.
///
/// Returns:
/// - [`ControlFlow::Break`] when the socket send failed (caller should
///   tear the connection down).
/// - [`ControlFlow::Continue`] when the inbox is drained (or the safety
///   cap was hit) and the connection should keep running.
#[cfg(feature = "tsp")]
async fn drain_tsp_inbox(
    state: &SharedData,
    session: &Session,
    socket: &mut WebSocket,
    ack_mode: bool,
    inflight: &mut std::collections::HashSet<String>,
) -> ControlFlow<(), ()> {
    let mut start_id: Option<String> = None;
    let mut total: usize = 0;
    // Every id this drain walked past (ack mode only) — used to prune `inflight`
    // once the walk completes, so ids the client has since acked (and which the
    // inbox therefore no longer returns) stop occupying the set.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();

    loop {
        let options = FetchOptions {
            limit: TSP_DRAIN_PAGE,
            start_id: start_id.clone(),
            ..Default::default() // delete_policy defaults to DoNotDelete; we delete explicitly.
        };
        let page = match state
            .database
            .fetch_messages(&session.session_id, &session.did_hash, &options)
            .await
        {
            Ok(page) => page,
            Err(err) => {
                warn!(
                    did_hash = %session.did_hash,
                    "TSP inbox drain fetch failed, aborting drain: {err}"
                );
                return ControlFlow::Continue(());
            }
        };
        if page.success.is_empty() {
            break;
        }

        for element in page.success {
            // Advance the cursor regardless of body presence so a missing body
            // can't pin the drain on the same page forever. `receive_id` is the
            // inbox stream id, used as the exclusive fetch cursor.
            start_id = element.receive_id.clone();

            let Some(body) = element.msg else { continue };
            // Deletion keys on `msg_id` (the message hash) — the same key the
            // optimistic-delete fetch path uses; `receive_id` is only the stream
            // cursor, not a valid delete key.
            let id = element.msg_id;
            if ack_mode {
                seen.insert(id.clone());
                // Already on the wire for this connection and not yet acked —
                // sending it again would duplicate within a single session.
                if inflight.contains(&id) {
                    continue;
                }
            }

            // Stored body is base64url(qb2). Decode back to raw qb2 bytes for
            // the wire. A malformed entry is skipped (not deleted) so it can be
            // inspected rather than silently dropped.
            let qb2 = match BASE64_URL_SAFE_NO_PAD.decode(&body) {
                Ok(bytes) => bytes,
                Err(err) => {
                    warn!(
                        did_hash = %session.did_hash,
                        message_id = %id,
                        "Skipping inbox entry that isn't valid base64url: {err}"
                    );
                    continue;
                }
            };

            if let Err(e) = socket.send(Message::Binary(qb2.into())).await {
                // The socket is gone — leave this message and the rest of the
                // inbox in place for the next connection (do NOT delete).
                warn!("Failed to send TSP message to WebSocket client: {e}");
                return ControlFlow::Break(());
            }

            if ack_mode {
                // Delete-to-ack: the write is not the acknowledgement, so keep
                // the message. The client deletes it once it has taken the
                // frame; until then it stays recoverable across a reconnect.
                inflight.insert(id.clone());
                debug!(
                    did_hash = %session.did_hash,
                    message_id = %id,
                    "Sent TSP message, awaiting client ack (tsp-ack mode)"
                );
            } else if let Err(err) = state
                // Delete-on-send: delivered as far as this mode is concerned. A
                // delete error is logged but not fatal — the frame is already
                // on the wire, so we continue.
                .database
                .delete_message(
                    &id,
                    DeletionAuthority::Owner {
                        did_hash: session.did_hash.clone(),
                    },
                )
                .await
            {
                warn!(
                    did_hash = %session.did_hash,
                    message_id = %id,
                    "Failed to delete delivered TSP message: {err}"
                );
            }

            total += 1;
            if total >= TSP_DRAIN_MAX {
                warn!(
                    did_hash = %session.did_hash,
                    max = TSP_DRAIN_MAX,
                    "TSP inbox drain hit its safety cap; remaining messages left for the next drain"
                );
                // Returns WITHOUT pruning `inflight` below, deliberately: only a
                // complete walk proves an absent id was acked, and pruning
                // against a walk cut short by the cap would resurrect
                // still-in-flight messages as duplicates.
                return ControlFlow::Continue(());
            }
        }
    }

    if ack_mode {
        // Anything no longer in the inbox has been acked (or expired): drop it
        // so the set tracks only what is genuinely outstanding.
        inflight.retain(|id| seen.contains(id));
    }

    if total > 0 {
        debug!(
            did_hash = %session.did_hash,
            total,
            awaiting_ack = inflight.len(),
            "TSP inbox drain complete"
        );
    }
    ControlFlow::Continue(())
}

/// Generates a problem report for a duplicate websocket connection
#[cfg(feature = "didcomm")]
fn _generate_duplicate_connection_problem_report() -> ProblemReport {
    ProblemReport::new(
        ProblemReportSorter::Warning,
        ProblemReportScope::Other("websocket".to_string()),
        "duplicate-channel".to_string(),
        "A new duplicate websocket connection for this DID has caused this websocket to terminate"
            .to_string(),
        vec![],
        None,
    )
}

/// Takes a problem report and packages it for sending to the recipient
#[cfg(feature = "didcomm")]
async fn _package_problem_report(
    state: &SharedData,
    session: &Session,
    msg_id: Option<String>,
    problem_report: ProblemReport,
) -> Result<String, MediatorError> {
    let mut pr_msg = DidcommMessage::build(
        Uuid::new_v4().to_string(),
        "https://didcomm.org/report-problem/2.0/problem-report".to_string(),
        json!(problem_report),
    )
    .from(state.config.mediator_did.clone())
    .to(session.did.to_string())
    .created_time(state.clock.unix_secs());

    if let Some(msg_id) = msg_id {
        pr_msg = pr_msg.pthid(msg_id);
    }

    let (packed, _) = didcomm_compat::pack_encrypted(
        &pr_msg.finalize(),
        &session.did,
        Some(&state.config.mediator_did),
        &state.did_resolver,
        &*state.config.security.mediator_secrets,
    )
    .await
    .map_err(|err| {
        MediatorError::MessagePackError(
            47,
            session.session_id.clone(),
            format!("Couldn't pack DIDComm message. Reason: {err}"),
        )
    })?;

    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::{
        CorsOriginPolicy, app_subprotocols, extract_bearer_subprotocol, ws_origin_allowed,
    };
    use crate::common::config::OriginMatcher;
    use http::HeaderValue;

    fn hv(s: &str) -> HeaderValue {
        HeaderValue::from_str(s).expect("valid header value")
    }

    fn exact(s: &str) -> OriginMatcher {
        OriginMatcher::Exact(hv(s))
    }

    #[test]
    fn extract_strips_prefix_and_preserves_jwt_dots() {
        // A JWT is three base64url segments joined by '.'. The bearer
        // entry must be prefix-stripped, not split, so the inner dots
        // survive intact.
        let protos = [hv("bearer.aaa.bbb.ccc")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("aaa.bbb.ccc".to_string())
        );
    }

    #[test]
    fn extract_finds_bearer_among_app_subprotocols() {
        // The browser may offer a genuine app subprotocol alongside the
        // bearer entry; the token must still be found regardless of order.
        let protos = [hv("didcomm/v2"), hv("bearer.tok.en.value")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("tok.en.value".to_string())
        );
    }

    #[test]
    fn extract_returns_none_without_bearer_entry() {
        let protos = [hv("didcomm/v2"), hv("soap")];
        assert_eq!(extract_bearer_subprotocol(protos.iter()), None);
    }

    #[test]
    fn extract_returns_none_for_empty_token() {
        // "bearer." with nothing after it is not a usable token.
        let protos = [hv("bearer.")];
        assert_eq!(extract_bearer_subprotocol(protos.iter()), None);
    }

    #[test]
    fn app_subprotocols_drops_bearer_entries() {
        // Guards the "never echo the token" requirement: the bearer
        // entry must be excluded from anything the server may reflect.
        let protos = [hv("didcomm/v2"), hv("bearer.secret.jwt.here")];
        assert_eq!(app_subprotocols(protos.iter()), vec!["didcomm/v2"]);
    }

    #[test]
    fn app_subprotocols_empty_when_only_bearer() {
        // Bearer-only offer ⇒ nothing safe to echo ⇒ no subprotocol
        // selected in the 101 response.
        let protos = [hv("bearer.secret.jwt.here")];
        assert!(app_subprotocols(protos.iter()).is_empty());
    }

    #[test]
    fn extract_bearer_from_comma_separated_header() {
        // RFC 6455: clients MAY send subprotocols as comma-separated in
        // a single Sec-WebSocket-Protocol header value.
        let protos = [hv("didcomm/v2, bearer.tok.en.value")];
        assert_eq!(
            extract_bearer_subprotocol(protos.iter()),
            Some("tok.en.value".to_string())
        );
    }

    #[test]
    fn app_subprotocols_from_comma_separated_header() {
        // Comma-separated bearer entry must be excluded, app protocols kept.
        let protos = [hv("didcomm/v2, bearer.secret.jwt.here")];
        assert_eq!(app_subprotocols(protos.iter()), vec!["didcomm/v2"]);
    }

    #[test]
    fn origin_check_allows_header_less_native_clients() {
        // Native clients (SDK) send no Origin — must always pass,
        // regardless of policy, since the JWT is their gate.
        assert!(ws_origin_allowed(&CorsOriginPolicy::None, None));
        assert!(ws_origin_allowed(&CorsOriginPolicy::Any, None));
        assert!(ws_origin_allowed(
            &CorsOriginPolicy::List(vec![exact("https://app.example")]),
            None
        ));
    }

    #[test]
    fn origin_check_none_policy_rejects_browser_origins() {
        let origin = hv("https://evil.example");
        assert!(!ws_origin_allowed(&CorsOriginPolicy::None, Some(&origin)));
    }

    #[test]
    fn origin_check_any_policy_allows_browser_origins() {
        let origin = hv("https://anything.example");
        assert!(ws_origin_allowed(&CorsOriginPolicy::Any, Some(&origin)));
    }

    #[test]
    fn origin_check_list_policy_matches_allowlist() {
        let policy = CorsOriginPolicy::List(vec![exact("https://app.example")]);
        let allowed = hv("https://app.example");
        let denied = hv("https://other.example");
        assert!(ws_origin_allowed(&policy, Some(&allowed)));
        assert!(!ws_origin_allowed(&policy, Some(&denied)));
    }

    #[test]
    fn origin_check_list_policy_honours_wildcards() {
        // Parity with the REST CORS layer: the WS check must accept the
        // same `*.suffix` wildcards (and reject the apex / look-alikes).
        let policy = CorsOriginPolicy::List(vec![OriginMatcher::WildcardSubdomain {
            scheme: "https".into(),
            suffix: "affinidi.com".into(),
            port: None,
        }]);
        assert!(ws_origin_allowed(
            &policy,
            Some(&hv("https://app.affinidi.com"))
        ));
        assert!(!ws_origin_allowed(
            &policy,
            Some(&hv("https://affinidi.com"))
        ));
        assert!(!ws_origin_allowed(
            &policy,
            Some(&hv("https://evilaffinidi.com"))
        ));
    }
}
