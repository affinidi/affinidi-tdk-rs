use crate::common::metrics::names::ACTIVE_WEBSOCKET_CONNECTIONS;
use crate::common::time::unix_timestamp_secs;
#[cfg(feature = "didcomm")]
use crate::didcomm_compat;
use crate::{
    SharedData,
    database::session::Session,
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
    response::IntoResponse,
};
use http::StatusCode;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{Instrument, debug, info, span, warn};
use uuid::Uuid;

/// Handles the switching of the protocol to a websocket connection
/// ACL_MODE: Requires LOCAL access
pub async fn websocket_handler(
    session: Session,
    ws: WebSocketUpgrade,
    State(state): State<SharedData>,
) -> impl IntoResponse {
    let _span = span!(
        tracing::Level::INFO,
        "websocket_handler",
        session = session.session_id
    );
    // ACL Check (websockets only work on local DID's)
    if session.acls.get_local() {
        async move { ws.on_upgrade(move |socket| handle_socket(socket, state, session)) }
            .instrument(_span)
            .await
    } else {
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

        error.into_response()
    }
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
                                if let Ok(msg) =  _package_problem_report(&state, &session, None, _generate_duplicate_connection_problem_report()).await {
                                    if let Err(e) = socket.send(Message::Text(msg.into())).await {
                                        warn!("Failed to send message to WebSocket client: {e}");
                                    }
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
