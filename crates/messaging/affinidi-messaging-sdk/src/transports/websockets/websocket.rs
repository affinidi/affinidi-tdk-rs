/*!
 * WebSocket transport implementation for Affinidi Messaging SDK.
 */

use super::{WebSocketResponses, ws_cache::MessageCache};
use crate::{ATM, SharedState, errors::ATMError, profiles::ATMProfile};
use ahash::{HashMap, HashMapExt};
use futures_util::{SinkExt, StreamExt};
use rand::RngExt;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    select,
    sync::{
        broadcast,
        mpsc::{self, Receiver, Sender},
        oneshot,
    },
    task::JoinHandle,
    time::{Interval, interval_at},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream,
    tungstenite::{Bytes, ClientRequestBuilder, Message, error::ProtocolError, http::Uri},
};
use tracing::{Instrument, Level, debug, error, span, warn};

type WebSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// A standalone task that manages the WebSocket connection to a mediator for a DID Profile
pub(crate) struct WebSocketTransport {
    /// The ATM Profile that this WebSocket connection is associated with
    pub(crate) profile: Arc<ATMProfile>,

    /// SDK Shared state
    shared: Arc<SharedState>,

    /// WebSocket Stream when connected
    web_socket: Option<WebSocket>,

    /// connect_delay_timer
    connect_delay_timer: Option<Interval>,

    /// Delay in seconds for the connection attempts
    /// Used to backoff the connection attempts
    connect_delay: u8,

    /// Counter tracking Websocket Ping/Pong responses
    /// Used to help with detecting when a websocket connection is lost
    awaiting_pong: bool,

    /// Unix-seconds expiry of the access token the current socket was opened
    /// with. The mediator force-closes the socket at this time, so we use it
    /// to proactively refresh the token and reconnect *before* expiry rather
    /// than waiting to be kicked. `None` until the first successful connect.
    access_expires_at: Option<u64>,

    /// Cache of inbound messages awaiting to be sent to the SDK
    /// If a MPSC delivery channel is enabled, then this cache isn't used
    inbound_cache: MessageCache,

    /// Possible to send messages to the SDK via a MPSC channel
    /// This bypasses the cache
    direct_channel: Option<broadcast::Sender<WebSocketResponses>>,

    /// Tracks number of next message requests from the SDK
    next_requests: HashMap<u32, oneshot::Sender<WebSocketResponses>>,
    next_requests_list: VecDeque<u32>,

    /// Skip calling toggle_live_delivery during connection setup
    skip_toggle_live_delivery: bool,

    /// Skip unpacking messages - return them as packed strings instead
    skip_unpack_messages: bool,
}

/// WebSocket Commands
pub(crate) enum WebSocketCommands {
    /// Stop the WebSocket Connection and shutdown the task
    Stop,

    /// Request to send a notifcation (true) if already connected or when next connects if not connected
    NotifyConnection(oneshot::Sender<bool>),

    /// Send a message to the mediator
    SendMessage(String),

    /// Send inbound messages to a MPSC Channel
    EnableInboundChannel(broadcast::Sender<WebSocketResponses>),

    /// Disable the inbound messages channel
    DisableInboundChannel,

    /// Get Next Message (will intercept before the InbOundChannel)
    /// U32: Unique ID for this request
    Next(u32, oneshot::Sender<WebSocketResponses>),

    /// Cancel this Next request
    CancelNext(u32),

    /// Get a specific message from the cache - will only respond if the message is found
    GetMessage(String, oneshot::Sender<WebSocketResponses>),

    /// If SDK timesout, then cancel the GetMessage request
    CancelGetMessage(String),
}

impl WebSocketTransport {
    /// Creates a new WebSocketTransport instance, it auto starts the websocket connection
    /// Returns a Future JoinHandle for this task and a Sender for sending commands to the task
    pub(crate) async fn start(
        profile: Arc<ATMProfile>,
        shared: Arc<SharedState>,
        direct_channel: Option<broadcast::Sender<WebSocketResponses>>,
    ) -> (JoinHandle<()>, Sender<WebSocketCommands>) {
        let (task_tx, mut task_rx) = mpsc::channel::<WebSocketCommands>(32);
        let handle = tokio::spawn(async move {
            let mut websocket = WebSocketTransport {
                profile: profile.clone(),
                shared: shared.clone(),
                web_socket: None,
                connect_delay_timer: None,
                connect_delay: 0,
                awaiting_pong: false,
                access_expires_at: None,
                inbound_cache: MessageCache {
                    fetch_cache_limit_count: shared.config.fetch_cache_limit_count,
                    fetch_cache_limit_bytes: shared.config.fetch_cache_limit_bytes,
                    ..Default::default()
                },
                direct_channel,
                next_requests: HashMap::new(),
                next_requests_list: VecDeque::new(),
                skip_toggle_live_delivery: false,
                skip_unpack_messages: false,
            };
            websocket.run(&mut task_rx).await;
        });
        (handle, task_tx)
    }

    pub(crate) async fn start_with_options(
        profile: Arc<ATMProfile>,
        shared: Arc<SharedState>,
        direct_channel: Option<broadcast::Sender<WebSocketResponses>>,
        skip_toggle_live_delivery: bool,
        skip_unpack_messages: bool,
    ) -> (JoinHandle<()>, Sender<WebSocketCommands>) {
        let (task_tx, mut task_rx) = mpsc::channel::<WebSocketCommands>(32);
        let handle = tokio::spawn(async move {
            let mut websocket = WebSocketTransport {
                profile: profile.clone(),
                shared: shared.clone(),
                web_socket: None,
                connect_delay_timer: None,
                connect_delay: 0,
                awaiting_pong: false,
                access_expires_at: None,
                inbound_cache: MessageCache {
                    fetch_cache_limit_count: shared.config.fetch_cache_limit_count,
                    fetch_cache_limit_bytes: shared.config.fetch_cache_limit_bytes,
                    ..Default::default()
                },
                direct_channel,
                next_requests: HashMap::new(),
                next_requests_list: VecDeque::new(),
                skip_toggle_live_delivery,
                skip_unpack_messages,
            };
            websocket.run(&mut task_rx).await;
        });
        (handle, task_tx)
    }

    /// Starts the WebSocket Connection and management to the mediator
    async fn run(&mut self, task_rx: &mut Receiver<WebSocketCommands>) {
        let _span = span!(Level::DEBUG, "websocket_run", profile = %self.profile.inner.alias);

        async move {
            // ATM utility for this connection
            let atm = ATM {
                inner: self.shared.clone(),
            };

            // Set up a watchdog to ping the mediator every 20 seconds
            let mut watchdog = interval_at(
                tokio::time::Instant::now() + Duration::from_secs(20),
                Duration::from_secs(20),
            );

            let mut notify_connection: Option<oneshot::Sender<bool>> = None;

            // Armed on each successful connect; drives a proactive token
            // refresh + reconnect before the mediator closes the socket at
            // access-token expiry.
            let mut refresh_deadline: Option<tokio::time::Instant> = None;

            loop {
                if self.web_socket.is_none() && self.connect_delay_timer.is_none() {
                    debug!("WebSocket not connected, starting connection attempt in {} seconds", self.connect_delay);
                    if self.connect_delay == 0 {
                        // Tick immediately
                        self.connect_delay_timer = Some(tokio::time::interval(Duration::from_secs(1)));
                    } else {
                        // Apply ±15% jitter so many clients disconnected at
                        // once don't reconnect in lock-step (thundering herd).
                        let delay = jittered_backoff(self.connect_delay);
                        self.connect_delay_timer = Some(tokio::time::interval_at(
                            tokio::time::Instant::now() + delay,
                            delay,
                        ));
                    }
                }

                select! {
                    Some(_) = WebSocketTransport::conditional_reconnect_delay(&mut self.connect_delay_timer), if self.web_socket.is_none() => {
                        debug!("Attempt to reconnect");
                        self.web_socket = self._handle_connection(&atm).await;
                        if self.web_socket.is_some() {
                            // Arm the proactive-refresh timer for this socket.
                            refresh_deadline = self.refresh_deadline();
                            if notify_connection.is_some() {
                                let _ = notify_connection.unwrap().send(true);
                                notify_connection = None;
                            }
                        }
                    },
                    Some(_) = Self::conditional_refresh(refresh_deadline), if self.web_socket.is_some() => {
                        debug!("Access token nearing expiry; refreshing and reconnecting");
                        refresh_deadline = None; // re-armed on the next connect
                        if let Ok((profile_did, mediator_did)) = self.profile.dids() {
                            // Mint a fresh access token via the refresh-token
                            // flow (mediator re-checks the DID is still allowed
                            // to connect) so the reconnect below carries a token
                            // good for another full lifetime.
                            if let Err(e) = self
                                .shared
                                .tdk_common
                                .authentication()
                                .refresh(profile_did.to_string(), mediator_did.to_string())
                                .await
                            {
                                warn!("Proactive token refresh failed ({e}); reconnecting to re-authenticate");
                            }
                        }
                        // Reconnect immediately (no backoff) so the new socket
                        // uses the fresh token before the old one expires.
                        if let Some(web_socket) = self.web_socket.as_mut() {
                            let _ = web_socket.close(None).await;
                        }
                        self.web_socket = None;
                        self.fail_pending_requests();
                        self.connect_delay = 0;
                        self.connect_delay_timer = None;
                    },
                    _ = watchdog.tick(), if self.web_socket.is_some() => {
                        if self.awaiting_pong {
                            warn!("Missed Pong, closing connection");
                            if let Some(web_socket) = self.web_socket.as_mut() {
                                let _ = web_socket.close(None).await;
                            }
                            self.web_socket = None;
                            self.fail_pending_requests();
                            self.backoff_delay();
                        } else if let Some(web_socket) = self.web_socket.as_mut() {
                            let _ = web_socket.send(Message::Ping(Bytes::new())).await;
                        }
                    },
                    cmd = task_rx.recv() => {
                        match cmd {
                            Some(WebSocketCommands::NotifyConnection(sender)) => {
                                if self.web_socket.is_some() {
                                    let _ = sender.send(self.web_socket.is_some());
                                } else {
                                    notify_connection = Some(sender);
                                }
                            },
                            Some(WebSocketCommands::SendMessage(msg)) => {
                                if let Some(web_socket) = self.web_socket.as_mut() {
                                    debug!("Sending message to websocket");
                                    match web_socket.send(Message::text(msg)).await {
                                        Ok(_) => {
                                            debug!("Message sent");
                                        }
                                        Err(e) => {
                                            error!("Error sending message: {:?}", e);
                                        }
                                    }
                                }
                            },
                            Some(WebSocketCommands::Stop) => {
                                debug!("Stopping WebSocket connection");
                                if let Some(web_socket) = self.web_socket.as_mut() {
                                    let _ = web_socket.close(None).await;
                                }
                                break;
                            },
                            Some(WebSocketCommands::EnableInboundChannel(sender)) => {
                                debug!("Enabling direct channel");
                                self.direct_channel = Some(sender);
                            },
                            Some(WebSocketCommands::DisableInboundChannel) => {
                                debug!("Disabling direct channel");
                                self.direct_channel = None;
                            },
                            Some(WebSocketCommands::Next(id, sender)) => {
                                debug!("Next message requested");
                                if let Some((message, metadata)) = self.inbound_cache.next() {
                                    let _ = sender.send(WebSocketResponses::MessageReceived(Box::new(message), Box::new(metadata)));
                                } else {
                                    self.next_requests.insert(id, sender);
                                    self.next_requests_list.push_back(id);
                                }
                            },
                            Some(WebSocketCommands::CancelNext(id)) => {
                                debug!("Next message cancelled");
                                self.next_requests.remove(&id);
                                self.next_requests_list.retain(|&x| x != id);

                            },
                            Some(WebSocketCommands::GetMessage(id, sender)) => {
                                if let Some((sender, message, metadata)) = self.inbound_cache.get_or_add_wanted(&id, sender) {
                                    debug!("Message found in cache");
                                    let _ = sender.send(WebSocketResponses::MessageReceived(Box::new(message), Box::new(metadata)));
                                } else {
                                    debug!("Message ({}) not found in cache, added to wanted list", id);
                                }
                            }
                            Some(WebSocketCommands::CancelGetMessage(_id)) => {
                                debug!("Get message cancelled");
                            }
                            None => break,
                        }
                    },
                    Some(msg) = WebSocketTransport::conditional_websocket(&mut self.web_socket), if !self.inbound_cache.is_full() => {
                        self.handle_inbound_message(&atm, msg).await;
                    }
                }
            }
            debug!("WebSocket connection stopped");
        }
        .instrument(_span)
        .await;
    }

    // Helper function that conditionally checks if the websocket is connected
    // Allows the use of an Option on the select! macro in the main loop
    async fn conditional_websocket(
        web_socket: &mut Option<WebSocket>,
    ) -> Option<
        Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    > {
        if let Some(ws) = web_socket.as_mut() {
            ws.next().await
        } else {
            None
        }
    }

    // Helper function that conditionally checks if reconnecting is needed
    // Allows the use of an Option on the select! macro in the main loop
    async fn conditional_reconnect_delay(delay: &mut Option<Interval>) -> Option<()> {
        if let Some(delay) = delay.as_mut() {
            delay.tick().await;
            Some(())
        } else {
            None
        }
    }

    /// Proactive token-refresh deadline for the freshly-connected socket:
    /// fire at ~80% of the access token's remaining lifetime, leaving the
    /// last ~20% as budget to refresh the token and reconnect *before* the
    /// mediator force-closes the socket at expiry. `None` if expiry is unknown.
    fn refresh_deadline(&self) -> Option<tokio::time::Instant> {
        let expires_at = self.access_expires_at?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let ttl = expires_at.saturating_sub(now);
        Some(tokio::time::Instant::now() + Duration::from_secs(refresh_after_secs(ttl)))
    }

    // Sleeps until the proactive-refresh deadline, if one is armed. Mirrors the
    // other `conditional_*` helpers so the `select!` branch simply never fires
    // when no deadline is set.
    async fn conditional_refresh(deadline: Option<tokio::time::Instant>) -> Option<()> {
        if let Some(deadline) = deadline {
            tokio::time::sleep_until(deadline).await;
            Some(())
        } else {
            None
        }
    }

    // Handles the inbound messages from the websocket
    async fn handle_inbound_message(
        &mut self,
        atm: &ATM,
        inbound: Result<Message, tokio_tungstenite::tungstenite::Error>,
    ) {
        match inbound {
            Ok(ws_msg) => match ws_msg {
                Message::Text(text) => {
                    debug!("Received inbound text message",);
                    self.process_inbound_didcomm_message(atm, text.to_string())
                        .await;
                }
                Message::Binary(data) => {
                    warn!("Received inbound binary message");
                    self.process_inbound_didcomm_message(
                        atm,
                        String::from_utf8_lossy(&data).to_string(),
                    )
                    .await;
                }
                Message::Ping(data) => {
                    debug!("Received ping message, sending pong");
                    if let Some(web_socket) = self.web_socket.as_mut() {
                        let _ = web_socket.send(Message::Pong(data)).await;
                    }
                }
                Message::Pong(_) => {
                    debug!("Received pong message");
                    self.awaiting_pong = false;
                }
                Message::Close(_) => {
                    debug!("WebSocket connection closed by server");
                    self.web_socket = None;
                    self.fail_pending_requests();
                    self.backoff_delay();
                }
                _ => {
                    warn!("Received unknown message type: {:?}", ws_msg);
                }
            },
            Err(tokio_tungstenite::tungstenite::Error::Protocol(
                ProtocolError::ResetWithoutClosingHandshake,
            )) => {
                // Connection Dropped
                warn!("WebSocket connection dropped");
                self.web_socket = None;
                self.fail_pending_requests();
                self.backoff_delay();
            }
            Err(e) => {
                error!("Generic websocket error: {:?}", e);
                self.web_socket = None;
                self.fail_pending_requests();
                self.backoff_delay();
            }
        }
    }

    async fn process_inbound_didcomm_message(&mut self, atm: &ATM, message: String) {
        debug!("Received text message ({})", message);

        // If skip_unpack_messages is true, send the packed message directly
        if self.skip_unpack_messages {
            // for packed messages skip cache lookup
            if let Some(next_request) = self.next_requests_list.pop_front() {
                debug!("Next message found, sending to requestor packed");
                if let Some(sender) = self.next_requests.remove(&next_request) {
                    let _ =
                        sender.send(WebSocketResponses::PackedMessageReceived(Box::new(message)));
                    return;
                } else {
                    error!(
                        "Next message requestor not found - bug in the SDK - inbound message may be lost"
                    );
                }
            }

            if let Some(direct_channel) = self.direct_channel.as_mut() {
                debug!("Sending message to direct channel packed");
                let _ = direct_channel
                    .send(WebSocketResponses::PackedMessageReceived(Box::new(message)));
            } else {
                debug!("No direct channel, should be cached");
            }
            return;
        }

        match atm.unpack(&message).await {
            Ok((message, metadata)) => {
                if let Some(sender) = self.inbound_cache.message_wanted(&message) {
                    debug!("Message is wanted, sending to requestor");
                    let _ = sender.send(WebSocketResponses::MessageReceived(
                        Box::new(message),
                        Box::new(metadata),
                    ));
                    return;
                }
                if let Some(next_request) = self.next_requests_list.pop_front() {
                    debug!("Next message found, sending to requestor");
                    if let Some(sender) = self.next_requests.remove(&next_request) {
                        let _ = sender.send(WebSocketResponses::MessageReceived(
                            Box::new(message.clone()),
                            Box::new(metadata),
                        ));
                        return;
                    } else {
                        error!(
                            "Next message requestor not found - bug in the SDK - inbound message may be lost"
                        );
                    }
                }

                if let Some(direct_channel) = self.direct_channel.as_mut() {
                    debug!("Sending message to direct channel");
                    let _ = direct_channel.send(WebSocketResponses::MessageReceived(
                        Box::new(message),
                        Box::new(metadata),
                    ));
                } else {
                    debug!("Caching message");
                    self.inbound_cache.insert(message, metadata);
                }
            }
            Err(e) => {
                error!("Error unpacking message: {:?}", e);
            }
        }
    }

    /// Notify every in-flight request waiter that the connection was lost.
    ///
    /// Called on each disconnect transition so callers (`live_stream_get` /
    /// `live_stream_next`) return immediately instead of blocking until their
    /// own timeout elapses. These requests are gone — the mediator never saw
    /// them, or their response was lost with the socket — so they will not be
    /// answered on the reconnected socket.
    fn fail_pending_requests(&mut self) {
        let mut notified = 0usize;

        // Pending `Next` waiters
        for (_, sender) in self.next_requests.drain() {
            let _ = sender.send(WebSocketResponses::Disconnected);
            notified += 1;
        }
        self.next_requests_list.clear();

        // Pending `GetMessage` (wanted) waiters
        for sender in self.inbound_cache.drain_wanted() {
            let _ = sender.send(WebSocketResponses::Disconnected);
            notified += 1;
        }

        if notified > 0 {
            debug!(
                count = notified,
                "Failed in-flight requests after websocket disconnect"
            );
        }
    }

    /// Calculate exponential backoff delay: 0→1→2→4→8→16→32→60s (capped).
    /// Jitter is applied separately at timer-creation time
    /// ([`jittered_backoff`]) so this base sequence stays deterministic.
    fn backoff_delay(&mut self) {
        self.connect_delay = match self.connect_delay {
            0 => 1,
            d if d < 60 => (d * 2).min(60),
            _ => 60,
        };
        self.connect_delay_timer = None;
    }

    // Wrapper that handles all of the logic of setting up a connection to the mediator
    async fn _handle_connection(&mut self, atm: &ATM) -> Option<WebSocket> {
        debug!("Starting websocket connection");

        let mut web_socket = match self._create_socket().await {
            Ok(ws) => ws,
            Err(e) => {
                error!("Error creating websocket connection: {:?}", e);
                self.backoff_delay();
                return None;
            }
        };

        debug!("Websocket connected. Next enable live streaming");

        // Do toggle_live_delivery on this socket if not skipped
        if self.skip_toggle_live_delivery {
            debug!("Skipping toggle_live_delivery as requested");
            self.connect_delay = 0;
            self.connect_delay_timer = None;
            self.awaiting_pong = false;
            Some(web_socket)
        } else {
            match atm
                .message_pickup()
                .toggle_live_delivery(&self.profile, true)
                .await
            {
                Ok(_) => {
                    debug!("Live streaming enabled");
                    self.connect_delay = 0;
                    self.connect_delay_timer = None;
                    self.awaiting_pong = false;
                    Some(web_socket)
                }
                Err(e) => {
                    error!("Error enabling live streaming: {:?}", e);
                    let _ = web_socket.close(None).await;
                    self.backoff_delay();
                    None
                }
            }
        }
    }

    // Responsible for creating a websocket connection to the mediator
    async fn _create_socket(&mut self) -> Result<WebSocket, ATMError> {
        let (profile_did, mediator_did) = self.profile.dids()?;
        // Check if authenticated
        let tokens = self
            .shared
            .tdk_common
            .authentication()
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;
        // Remember when this token expires so we can refresh+reconnect before
        // the mediator force-closes the socket at expiry.
        self.access_expires_at = Some(tokens.access_expires_at);

        debug!("Creating websocket connection");
        // Create a custom websocket request, turn this into a client_request
        // Allows adding custom headers later

        let Some(mediator) = &*self.profile.inner.mediator else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid mediator configuration!",
                self.profile.inner.alias
            )));
        };

        let Some(address) = &mediator.websocket_endpoint else {
            return Err(ATMError::ConfigError(format!(
                "Profile ({}) is missing a valid websocket endpoint!",
                self.profile.inner.alias
            )));
        };

        let uri: Uri = match address.parse() {
            Ok(uri) => uri,
            Err(err) => {
                error!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                );
                return Err(ATMError::TransportError(format!(
                    "Mediator {}: Invalid ServiceEndpoint address {}: {}",
                    mediator.did, address, err
                )));
            }
        };

        let host = uri.host().unwrap_or_default().to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });

        let builder = ClientRequestBuilder::new(uri)
            .with_header("Authorization", ["Bearer ", &tokens.access_token].concat());

        let (web_socket, _) = super::proxy::connect_websocket(builder, &host, port)
            .await
            .map_err(|e| {
                ATMError::TransportError(format!(
                    "Profile '{}' → mediator {} websocket {} ({}:{}): {}",
                    self.profile.inner.alias, mediator.did, address, host, port, e
                ))
            })?;

        debug!("Completed websocket connection");

        Ok(web_socket)
    }
}

impl std::fmt::Debug for WebSocketTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebSocketTransport")
            .field("profile", &self.profile)
            .field("web_socket", &self.web_socket.is_some())
            .field("connect_delay", &self.connect_delay)
            .field("awaiting_pong", &self.awaiting_pong)
            .field("skip_toggle_live_delivery", &self.skip_toggle_live_delivery)
            .field("skip_unpack_messages", &self.skip_unpack_messages)
            .finish()
    }
}

/// Apply ±15% random jitter to a base backoff delay (in seconds). When the
/// mediator recovers, clients that all disconnected together would otherwise
/// reconnect in lock-step and stampede it; jitter spreads the reconnections
/// out. Non-cryptographic randomness is fine here.
fn jittered_backoff(base_secs: u8) -> Duration {
    let factor = rand::rng().random_range(0.85..1.15);
    Duration::from_secs_f64(base_secs as f64 * factor)
}

/// How long after connecting to proactively refresh the access token and
/// reconnect: 80% of the token's remaining lifetime, leaving the final ~20%
/// as budget to refresh + reconnect before the mediator force-closes the
/// socket at expiry.
fn refresh_after_secs(ttl_secs: u64) -> u64 {
    // `*4` first for accuracy on short TTLs; token lifetimes can't overflow u64.
    (ttl_secs * 4) / 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_fires_before_expiry_with_budget_to_spare() {
        // Always strictly before expiry (so we beat the mediator's forced
        // close) and never zero for a non-trivial TTL (so we don't hot-loop).
        for ttl in [10u64, 60, 300, 900, 86_400] {
            let after = refresh_after_secs(ttl);
            assert!(
                after < ttl,
                "ttl {ttl}: refresh at {after} not before expiry"
            );
            assert!(after > 0, "ttl {ttl}: refresh delay must be positive");
            // ~80% of the lifetime.
            assert_eq!(after, (ttl * 4) / 5);
        }
        // Degenerate inputs don't panic.
        assert_eq!(refresh_after_secs(0), 0);
        assert_eq!(refresh_after_secs(1), 0);
    }

    #[test]
    fn jittered_backoff_stays_within_15_percent() {
        // Sample repeatedly: every jittered delay must land within ±15% of
        // the base and never be zero/negative.
        for base in [1u8, 2, 4, 8, 16, 32, 60] {
            for _ in 0..1000 {
                let d = jittered_backoff(base).as_secs_f64();
                assert!(
                    d >= base as f64 * 0.85 && d < base as f64 * 1.15,
                    "jittered {base}s -> {d}s out of ±15% band"
                );
                assert!(d > 0.0);
            }
        }
    }
}
