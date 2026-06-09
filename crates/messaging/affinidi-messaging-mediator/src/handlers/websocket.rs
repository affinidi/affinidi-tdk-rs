use crate::common::metrics::names::ACTIVE_WEBSOCKET_CONNECTIONS;
use crate::common::time::unix_timestamp_secs;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
use crate::{
    SharedData,
    common::config::{CorsOriginPolicy, origin_matches},
    common::jwt_auth::{AuthError, authenticate_token},
    common::session::Session,
    messages::inbound::handle_inbound,
    tasks::websocket_streaming::{StreamingUpdate, StreamingUpdateState, WebSocketCommands},
};
#[cfg(feature = "didcomm")]
use affinidi_messaging_didcomm::message::Message as DidcommMessage;
use affinidi_messaging_mediator_common::errors::{AppError, MediatorError};
use affinidi_messaging_sdk::messages::problem_report::{
    ProblemReport, ProblemReportScope, ProblemReportSorter,
};
use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::{IntoResponse, Response},
};
use axum_extra::{
    TypedHeader,
    headers::{Authorization, authorization::Bearer},
};
use http::{HeaderMap, HeaderValue, StatusCode, header::ORIGIN, header::SEC_WEBSOCKET_PROTOCOL};
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{Instrument, debug, info, span, warn};
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

    async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
        .instrument(_span)
        .await
}

/// WebSocket state machine. This is spawned per connection.
async fn handle_socket(mut socket: WebSocket, state: SharedData, session: Session) {
    let _span = span!(
        tracing::Level::INFO,
        "handle_socket",
        session = session.session_id
    );
    async move {
        // Enforce connection limit
        let current = state.active_websocket_count.fetch_add(1, Ordering::Relaxed);
        if current >= state.config.limits.max_websocket_connections {
            state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
            warn!("WebSocket connection limit reached ({}/{})", current, state.config.limits.max_websocket_connections);
            let _ = socket.send(Message::Close(None)).await;
            return;
        }

        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).increment(1.0);

        // Register the transmission channel between websocket_streaming task and this websocket.
        let (tx, mut rx): (Sender<WebSocketCommands>, Receiver<WebSocketCommands>) = mpsc::channel(5);
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
        }

        let _ = state.database.global_stats_increment_websocket_open().await;
        info!("Websocket connection established");

        // Set a timeout for the websocket connection for when the JWT Auth token expires
        let epoch = unix_timestamp_secs();
        if session.expires_at <= epoch {
            warn!("JWT access token has expired. Closing Session");
            return;
        }
        let auth_timeout = tokio::time::sleep(Duration::from_secs(session.expires_at - epoch));
        tokio::pin!(auth_timeout);
        debug!(expires_in_secs = session.expires_at - epoch, "WebSocket auth timeout set");

        // Periodic ping to detect dead connections
        let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
        ping_interval.reset(); // Skip the immediate first tick

        // Flag to prevent double deregistration
        // This can occur because in some situations the streaming-task will send a close message
        // due to duplicate channels. If we were to deregister on close in this scenario, we would
        // also deregister the new channel that is still in use.
        let mut already_deregistered_flag = false;
        loop {
            select! {
                _ = &mut auth_timeout => {
                    debug!("Auth Timeout reached");
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
                        break;
                    }}
                }
                _ = ping_interval.tick() => {
                    if let Err(e) = socket.send(Message::Ping(vec![].into())).await {
                        debug!("Failed to send WebSocket ping: {e}");
                        break;
                    }
                }
                value = rx.recv() => {
                    if let Some(msg) = value {
                        match msg {
                            WebSocketCommands::Message(msg) => {
                                debug!("ws: Received message from streaming task");
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
                                break;
                            }
                        }
                    } else {
                        debug!("Received None from streaming task, closing connection");
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
                    state: StreamingUpdateState::Deregister,
                };
                let _ = streaming.channel.send(stop).await;
            }
        }

        state.active_websocket_count.fetch_sub(1, Ordering::Relaxed);
        metrics::gauge!(ACTIVE_WEBSOCKET_CONNECTIONS).decrement(1.0);

        // We're done, close the connection
        if let Err(e) = socket.send(Message::Close(None)).await {
            debug!("Failed to send WebSocket close frame: {e}");
        }
        let _ = state
            .database
            .global_stats_increment_websocket_close()
            .await;

        info!("Websocket connection closed");
    }
    .instrument(_span)
    .await
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
    .created_time(unix_timestamp_secs());

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
