/*!
 * WebSocket handler - responsible for managing multiple WebSocket connections
 */
use super::SharedState;
use crate::{
    ATM,
    errors::ATMError,
    profiles::ATMProfile,
    transports::{
        WsConnectionCommands,
        websockets::{ws_cache::MessageCache, ws_connection::WsConnection},
    },
};
use affinidi_messaging_didcomm::{Message, UnpackMetadata};
use ahash::AHashMap as HashMap;
use std::{
    fmt::{self, Debug, Formatter},
    sync::Arc,
};
use tokio::{
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tracing::{Instrument, Level, debug, info, span, warn};

/// The mode in which the handler should operate
/// Cached: Messages are cached and sent to the SDK when requested
/// DirectChannel: Messages are sent directly to the SDK without caching
#[derive(Clone)]
pub enum WsHandlerMode {
    Cached,
    DirectChannel,
}

impl Debug for WsHandlerMode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            WsHandlerMode::Cached => write!(f, "Cached"),
            WsHandlerMode::DirectChannel => write!(f, "DirectChannel"),
        }
    }
}

/// Possible messages that can be sent to the websocket handler
#[derive(Clone, Debug)]
pub enum WsHandlerCommands {
    // Messages sent from SDK to the Handler
    Exit,
    Activate(Arc<ATMProfile>),
    Deactivate(Arc<ATMProfile>),
    Next,                                   // Gets the next message from the cache
    CancelNext,                             // Cancels the next message request
    Get(String, Sender<WsHandlerCommands>), // Gets the message with the specified ID from the cache
    TimeOut(Arc<ATMProfile>, String), // SDK request timed out, contains msg_id we were looking for
    // Messages sent from Handler to the SDK
    Started, // WsHandler has started and is ready to work
    MessageReceived(Message, Box<UnpackMetadata>), // Message received from the websocket
    NotFound, // Message not found in the cache
    // Messages sent from the Handler to a specific Profile
    Activated(String), // Profile WebSocket connection is active (status_message to get)
    Disconnected(),    // Profile Websocket connection is disconnected
    InDirectChannelModeError, // WsHandler is in DirectChannelMode and is not caching messages
}

impl ATM {
    /// WebSocket streaming handler
    /// from_sdk is an MPSC channel used to receive messages from the main thread that will be sent to the websocket
    /// to_sdk is an MPSC channel used to send messages to the main thread that were received from the websocket
    pub(crate) async fn ws_handler(
        shared_state: Arc<SharedState>,
        from_sdk: &mut Receiver<WsHandlerCommands>,
        to_sdk: Sender<WsHandlerCommands>,
    ) -> Result<(), ATMError> {
        let _span = span!(Level::INFO, "ws_handler");
        async move {
            let ws_handler_mode = shared_state.config.ws_handler_mode.clone();
            debug!("Starting websocket handler. Mode: {:?}", ws_handler_mode);

            // Set up a message cache
            let mut cache = MessageCache {
                fetch_cache_limit_count: shared_state.config.fetch_cache_limit_count,
                fetch_cache_limit_bytes: shared_state.config.fetch_cache_limit_bytes,
                ..Default::default()};

            // A list of all the active connections
            let mut connections: HashMap<String, Arc<ATMProfile>> = HashMap::new();

            // Set up the channel for WS_Connections to communicate to the handler
            // Create a new channel with a capacity of at most 32. This communicates from WS_Connections to the WS_Handler
            let ( handler_tx, mut handler_rx) = mpsc::channel::<WsConnectionCommands>(32);

            to_sdk.send(WsHandlerCommands::Started).await.map_err(|err| {
                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
            })?;

            // Used to track outstanding next message requests
            let mut next_counter = 0;

            loop {
                select! {
                    value = handler_rx.recv(), if !cache.is_full() => {
                        // These are inbound messages from the WS_Connections
                        match value { Some(message) => {
                            match message {
                                WsConnectionCommands::Connected(profile, status_msg_id) => {
                                    // Send a message to the SDK that the profile has connected
                                    match profile.inner.channel_tx.lock().await.try_send(WsHandlerCommands::Activated(status_msg_id)) {
                                        Ok(_) => {
                                            debug!("Profile({}): Sent Activated message", profile.inner.alias);
                                        }
                                        Err(err) => {
                                            debug!("Profile({}): SDK_TX Channel is full: {:?}", profile.inner.alias, err);
                                        }
                                    }
                                }
                                WsConnectionCommands::Disconnected(profile) => {
                                    // Send a message to the SDK that the profile has disconnected
                                    match profile.inner.channel_tx.lock().await.try_send(WsHandlerCommands::Disconnected()) {
                                        Ok(_) => {
                                            debug!("Profile({}): Sent Disconnected message", profile.inner.alias);
                                        }
                                        Err(err) => {
                                            debug!("Profile({}): SDK_TX Channel is full: {:?}", profile.inner.alias, err);
                                        }
                                    }
                                }
                                WsConnectionCommands::MessageReceived(data) => {
                                    let (message, meta) = *data;
                                    debug!("Message received from WS_Connection");
                                    if let WsHandlerMode::Cached = ws_handler_mode {
                                        // If we are in cached mode, we need to cache the message
                                        match cache.search(&message.id, message.thid.as_deref(), message.pthid.as_deref()) { Some(channel) => {
                                            debug!("Message found in cache");
                                            // notify the SDK that a message has been found
                                            let _ = channel.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await;
                                            debug!("Message delivered to receive channel");
                                        } _ => if next_counter > 0 {
                                                next_counter -= 1;
                                                to_sdk.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                                    ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                                })?;
                                            } else {
                                                cache.insert(message, meta);
                                            }}
                                    } else {
                                        // Send the message directly to the broadcast channel
                                        if let Some(broadcast) = &shared_state.direct_stream_sender {
                                            let _ = broadcast.send((message, meta));
                                        }
                                    }
                                }
                                _ => {
                                    warn!("Received unknown message from WS_Connection");
                                }
                            }
                        } _ => {
                            warn!("Channel to_handler closed");
                        }}
                    }
                    value = from_sdk.recv() => {
                        match value { Some(cmd) => {
                            match cmd {
                                WsHandlerCommands::Activate(profile) => {
                                    debug!("Profile({}): Activating", profile.inner.alias);
                                    let ( connection_tx, connection_rx) = mpsc::channel::<WsConnectionCommands>(32);
                                    match WsConnection::activate(shared_state.clone(), &profile, handler_tx.clone(), connection_rx, connection_tx.clone()).await {
                                        Ok(_) => {
                                            connections.insert(profile.inner.alias.clone(), profile.clone());
                                            debug!("Profile({}): Activated", profile.inner.alias);
                                        }
                                        Err(err) => {
                                            warn!("Profile({}): Could not activate: {:?}", profile.inner.alias, err);
                                        }
                                    }
                                }
                                WsHandlerCommands::Deactivate(profile) => {
                                    debug!("Profile({}): Shutting Down", profile.inner.alias);
                                    if let Some(profile) = connections.remove(&profile.inner.alias) {
                                        if let Some(mediator) = &*profile.inner.mediator {
                                            if let Some(channel) = &*mediator.ws_channel_tx.lock().await {
                                                let _ = channel.send(WsConnectionCommands::Stop).await;
                                            }
                                        }
                                    }
                                }
                                WsHandlerCommands::Next => {
                                    if let WsHandlerMode::Cached = ws_handler_mode {
                                        match cache.next() { Some((message, meta)) => {
                                            to_sdk.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                            })?;
                                        } _ => {
                                            next_counter += 1;
                                        }}
                                    } else {
                                        to_sdk.send(WsHandlerCommands::InDirectChannelModeError).await.map_err(|err| {
                                            ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                        })?;
                                    }
                                }
                                WsHandlerCommands::CancelNext => {
                                    next_counter -= 1;
                                }
                                WsHandlerCommands::Get(id, channel) => {
                                    if let WsHandlerMode::Cached = ws_handler_mode {
                                        match cache.get(&id, &channel) { Some((message, meta)) => {
                                            channel.send(WsHandlerCommands::MessageReceived(message, Box::new(meta))).await.map_err(|err| {
                                                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                            })?;
                                        } _ => {
                                            channel.send(WsHandlerCommands::NotFound).await.map_err(|err| {
                                                ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                            })?;
                                        }}
                                    } else {
                                        to_sdk.send(WsHandlerCommands::InDirectChannelModeError).await.map_err(|err| {
                                            ATMError::TransportError(format!("Could not send message to SDK: {:?}", err))
                                        })?;
                                    }
                                }
                                WsHandlerCommands::Exit => {
                                    debug!("Received EXIT message, closing channels");
                                    for (alias, profile) in connections.iter() {
                                        debug!("Profile({}): Sent Stop Command", alias);
                                        {
                                            if let Some(mediator) = &*profile.inner.mediator {
                                                if let Some(channel) = &*mediator.ws_channel_tx.lock().await {
                                                    let _ = channel.send(WsConnectionCommands::Stop).await;
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                                WsHandlerCommands::TimeOut(_, id) => {
                                    cache.search_list.remove(&id);
                                }
                                _ => {
                                    warn!("Received unknown command");
                                }
                            }
                        } _ => {
                            info!("Channel Closed");
                            break;
                        }}
                    }
                }
            }

            from_sdk.close();

            debug!("Channel closed, stopping websocket handler");
            Ok(())
        }
        .instrument(_span)
        .await
    }
}
