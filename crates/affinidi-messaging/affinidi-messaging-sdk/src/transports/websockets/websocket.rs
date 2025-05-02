/*!
 * WebSocket transport implementation for Affinidi Messaging SDK.
 */

use super::{WebSocketResponses, ws_cache::MessageCache};
use crate::{ATM, SharedState, errors::ATMError, profiles::ATMProfile, protocols::Protocols};
use ahash::{HashMap, HashMapExt};
use futures_util::{SinkExt, StreamExt};
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
    MaybeTlsStream, WebSocketStream, connect_async,
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

    /// Cache of inbound messages awaiting to be sent to the SDK
    /// If a MPSC delivery channel is enabled, then this cache isn't used
    inbound_cache: MessageCache,

    /// Possible to send messages to the SDK via a MPSC channel
    /// This bypasses the cache
    direct_channel: Option<broadcast::Sender<WebSocketResponses>>,

    /// Tracks number of next message requests from the SDK
    next_requests: HashMap<u32, oneshot::Sender<WebSocketResponses>>,
    next_requests_list: VecDeque<u32>,
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
                inbound_cache: MessageCache {
                    fetch_cache_limit_count: shared.config.fetch_cache_limit_count,
                    fetch_cache_limit_bytes: shared.config.fetch_cache_limit_bytes,
                    ..Default::default()
                },
                direct_channel,
                next_requests: HashMap::new(),
                next_requests_list: VecDeque::new(),
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
            let protocols = Protocols::new();

            // Set up a watchdog to ping the mediator every 20 seconds
            let mut watchdog = interval_at(
                tokio::time::Instant::now() + Duration::from_secs(20),
                Duration::from_secs(20),
            );

            let mut notify_connection: Option<oneshot::Sender<bool>> = None;

            loop {
                if self.web_socket.is_none() && self.connect_delay_timer.is_none() {
                    debug!("WebSocket not connected, starting connection attempt in {} seconds", self.connect_delay);
                    if self.connect_delay == 0 {
                        // Tick immediately
                        self.connect_delay_timer = Some(tokio::time::interval(Duration::from_secs(1)));
                    } else {
                        self.connect_delay_timer = Some(tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(self.connect_delay as u64),Duration::from_secs(
                            self.connect_delay as u64,
                        )));
                    }
                }

                select! {
                    Some(_) = WebSocketTransport::conditional_reconnect_delay(&mut self.connect_delay_timer), if self.web_socket.is_none() => {
                        debug!("Attempt to reconnect");
                        self.web_socket = self._handle_connection(&atm, &protocols).await;
                        if self.web_socket.is_some() && notify_connection.is_some() {
                            let _ = notify_connection.unwrap().send(true);
                            notify_connection = None;
                        }
                    },
                    _ = watchdog.tick(), if self.web_socket.is_some() => {
                        if self.awaiting_pong {
                            debug!("Missed Pong, closing connection");
                            if let Some(web_socket) = self.web_socket.as_mut() {
                                let _ = web_socket.close(None).await;
                            }
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
                                    let _ = sender.send(WebSocketResponses::MessageReceived(message, Box::new(metadata)));
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
                                    let _ = sender.send(WebSocketResponses::MessageReceived(message, Box::new(metadata)));
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
                Message::Pong(_) => {
                    debug!("Received pong message");
                    self.awaiting_pong = false;
                }
                Message::Close(_) => {
                    debug!("WebSocket connection closed");
                    self.web_socket = None;
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
            }
            Err(e) => {
                error!("Generic websocket error: {:?}", e);
                self.web_socket = None;
            }
        }
    }

    async fn process_inbound_didcomm_message(&mut self, atm: &ATM, message: String) {
        debug!("Received text message ({})", message);
        match atm.unpack(&message).await {
            Ok((message, metadata)) => {
                if let Some(sender) = self.inbound_cache.message_wanted(&message) {
                    debug!("Message is wanted, sending to requestor");
                    let _ = sender.send(WebSocketResponses::MessageReceived(
                        message,
                        Box::new(metadata),
                    ));
                    return;
                }
                if let Some(next_request) = self.next_requests_list.pop_front() {
                    debug!("Next message found, sending to requestor");
                    if let Some(sender) = self.next_requests.remove(&next_request) {
                        let _ = sender.send(WebSocketResponses::MessageReceived(
                            message.clone(),
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
                        message,
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

    // Wrapper that handles all of the logic of setting up a connection to the mediator
    async fn _handle_connection(&mut self, atm: &ATM, protocols: &Protocols) -> Option<WebSocket> {
        debug!("Starting websocket connection");

        fn _calculate_delay(delay: u8) -> u8 {
            let delay = if delay == 0 {
                1
            } else if delay < 60 {
                delay * 2
            } else {
                delay
            };

            if delay > 60 { 60 } else { delay }
        }

        let mut web_socket = match self._create_socket().await {
            Ok(ws) => ws,
            Err(e) => {
                error!("Error creating websocket connection: {:?}", e);
                self.connect_delay = _calculate_delay(self.connect_delay);
                self.connect_delay_timer = None;
                return None;
            }
        };

        debug!("Websocket connected. Next enable live streaming");

        // Enable live_streaming on this socket
        match protocols
            .message_pickup
            .toggle_live_delivery(atm, &self.profile, true)
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
                self.connect_delay = _calculate_delay(self.connect_delay);
                self.connect_delay_timer = None;
                None
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
            .authentication
            .authenticate(profile_did.to_string(), mediator_did.to_string(), 3, None)
            .await?;

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

        let builder = ClientRequestBuilder::new(uri)
            .with_header("Authorization", ["Bearer ", &tokens.access_token].concat());

        let web_socket = match connect_async(builder).await {
            Ok((web_socket, _)) => web_socket,
            Err(err) => {
                warn!("WebSocket failed. Reason: {}", err);
                return Err(ATMError::TransportError(format!(
                    "Websocket connection failed: {}",
                    err
                )));
            }
        };

        debug!("Completed websocket connection");

        Ok(web_socket)
    }
}
